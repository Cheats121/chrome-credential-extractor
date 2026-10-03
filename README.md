# Chrome Login Data Extractor

A Python-based forensics tool for analyzing Chrome credential artifacts protected by Windows DPAPI.

## Features

- Helps with extraction of chrome browser credentials.

## Requirements

- Python 3
- PyCryptodome

Install the required package with:

```bash
pip install pycryptodome
```

## Usage

Run the script with:

```bash
python script.py
```

The program provides a menu for analyzing Chrome and DPAPI artifacts and decrypting Chrome login data.

You will need an extracted Windows evidence directory containing the relevant Chrome and DPAPI files.

For password decryption, the script also requires the recovered Windows account password associated with the DPAPI masterkey.

## How It Works

The script first searches the supplied evidence directory for Windows DPAPI masterkeys and Chrome browser artifacts.

It then reads Chrome's `Local State` file to find the DPAPI-protected Chrome encryption key and identifies which Windows masterkey is required.

After the correct Windows password is provided, the script attempts to unlock the DPAPI masterkey. It then uses that masterkey to decrypt Chrome's AES key.

The recovered Chrome AES key is then used to decrypt supported password entries stored inside Chrome's `Login Data` SQLite database.

## Supported Password Formats

Currently supported:

- `v10`
- `v11`

## Notes

The script works with copied or extracted forensic evidence and creates temporary copies of Chrome databases when reading them so the original evidence is not modified.

## Credits and Acknowledgements

This project was built for educational, CTF, and digital forensics purposes.

Parts of the DPAPI parsing and decryption logic were inspired by the following open-source projects:

- **John the Ripper / DPAPImk2john.py**  
  Openwall / John the Ripper contributors  
  https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py

- **mimikatz**  
  Benjamin Delpy (gentilkiwi)  
  https://github.com/gentilkiwi/mimikatz

These projects were extremely helpful for building this tool.

All credit for the original implementations and research belongs to these authors.

Please refer to the original projects for their applicable licensing terms.

## Author

Cheats121
