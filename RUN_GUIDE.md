# AES-256 File Security — Run Guide

## Requirements
- Python 3.10+ recommended
- Tkinter (included with the standard Windows Python installer)
- PyCryptodome

## Install on Windows

Open Command Prompt in the repository folder:

```bash
python -m venv venv
venv\\Scripts\\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Run

```bash
python main.py
```

## Test

```bash
python -m unittest discover -s tests -v
```

The test suite checks:
- encryption/decryption round trip
- empty-file handling
- wrong-password rejection
- authentication/tamper rejection

## Use
1. Select a normal file.
2. Enter a password of at least 8 characters and confirm it.
3. Click **Encrypt**. The encrypted file is saved with `.aes`.
4. Select the `.aes` file.
5. Enter the password; confirmation is not required for decryption.
6. Click **Decrypt**.

This is an educational encryption project. For production systems, use a reviewed cryptographic library and a proper key-management design.
