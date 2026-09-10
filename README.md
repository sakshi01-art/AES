# 🛡️ AES-256-GCM Enterprise Cryptographic Suite
### *NIST SP 800-38D Compliant Authenticated Encryption System*

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Security](https://img.shields.io/badge/Cipher-AES--256--GCM-emerald.svg)]()
[![Standard](https://img.shields.io/badge/Standard-NIST%20SP%20800--38D-informational.svg)]()
[![Shredder](https://img.shields.io/badge/Sanitization-DoD%205220.22--M-red.svg)]()
[![UI](https://img.shields.io/badge/GUI-CustomTkinter%20Dark-purple.svg)]()

An enterprise-grade, high-throughput cryptographic desktop application providing **Authenticated Encryption with Associated Data (AEAD)**, secure directory archiving, DoD 3-pass file shredding, Shannon entropy analysis, and non-blocking asynchronous task execution.

---

## 🌟 Key Engineering Features

- 🔐 **AES-256 in Galois/Counter Mode (GCM)**: Authenticated encryption providing simultaneous confidentiality and integrity verification. Immune to Padding Oracle attacks.
- ⚡ **O(1) Streaming Engine**: 1 MB chunked memory buffering enabling encryption of multi-gigabyte files with a constant, minimal RAM footprint (< 25 MB).
- 🏷️ **Cryptographic Metadata Header**: Automatically encapsulates original filenames, file extensions, permissions, and SHA-256 checksums inside the encrypted payload.
- 📁 **Full Directory & Archive Support**: Encrypts and decrypts entire folder hierarchies while defending against **Zip Slip** directory traversal vulnerabilities.
- 💬 **Secret Message Vault**: Live Base64-armored string encryption and decryption for secure notes and credentials.
- 💥 **DoD 5220.22-M File Shredder**: Optional 3-pass military-grade sanitization (0x00, 0xFF, CSPRNG noise, OS flush) to prevent forensic data recovery.
- 🔑 **Password & Entropy Studio**: Calculates pool and Shannon entropy in bits, evaluates password resilience against brute-force attacks, and generates high-entropy passwords using CSPRNG (`secrets`).
- 🚀 **Multithreaded Responsive GUI**: Asynchronous worker threads with thread-safe UI updates, real-time throughput metrics (MB/s), ETA calculation, and cancellation tokens.
- 🔄 **Backward Compatibility**: Seamlessly detects and decrypts Legacy Version 1 `.aes` files.

---

## 📐 Binary Specification Layout (V2 Payload)

```
+----------------+----------------+-----------------+-----------------+
|  MAGIC (6 B)   |  VERSION (1 B) |   SALT (16 B)   |   NONCE (12 B)  |
|   "AESGCM"     |      0x02      |   CSPRNG Salt   |   96-bit Nonce  |
+----------------+----------------+-----------------+-----------------+
| META_LEN (4 B) |   ENCRYPTED METADATA JSON (Filename, Hash, Size)   |
+----------------+----------------------------------------------------+
|                  CIPHERTEXT PAYLOAD STREAM (1 MB Chunks)            |
+---------------------------------------------------------------------+
|                      GCM AUTHENTICATION TAG (16 B)                  |
+---------------------------------------------------------------------+
```

---

## 📂 Project Structure

```
AES_/
├── core/
│   ├── __init__.py
│   ├── crypto_engine.py       # AES-256-GCM streaming encryption/decryption, PBKDF2
│   ├── folder_processor.py    # Recursive zip packaging with Zip Slip defense
│   ├── shredder.py            # DoD 5220.22-M 3-pass cryptographic file shredder
│   └── password_manager.py    # Shannon entropy calculator & CSPRNG generator
├── gui/
│   ├── __init__.py
│   └── app.py                 # Modern CustomTkinter dark-mode UI
├── tests/
│   ├── __init__.py
│   └── test_crypto.py         # Automated unit test suite
├── main.py                    # Application launch entry point
├── requirements.txt           # Dependency specifications
├── README.md                  # Comprehensive project documentation
└── INTERVIEW_GUIDE.md         # Full technical interview Q&A guide
```

---

## 🚀 Quickstart & Installation

### 1. Prerequisites
Ensure Python 3.10+ is installed on your system.

### 2. Setup Virtual Environment
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Run the Application
```bash
python main.py
```

---

## 🧪 Automated Testing

Execute the test suite validating all cryptographic properties (roundtrip integrity, tamper detection, folder recursion, entropy calculations, and DoD shredding):

```bash
python -m unittest tests/test_crypto.py
```

Expected output:
```
Ran 8 tests in ~2.5s
OK
```

---

## 🛡️ Security Guarantees & Threat Model

| Threat / Attack Vector | Mitigation Strategy in this System |
|---|---|
| **Ciphertext Bit-Flipping** | 128-bit GHASH Authentication Tag validated before committing plaintext to disk. |
| **Padding Oracle Attack** | Eliminated entirely by using Counter Mode (CTR) inside GCM (no PKCS#7 padding needed). |
| **GPU / ASIC Brute-Force** | PBKDF2 key derivation configured with **250,000 SHA-256 iterations**. |
| **Rainbow Table Attacks** | Unique, cryptographically secure 16-byte random salt per encryption operation. |
| **Out-Of-Memory (OOM) Denial** | Streaming buffer architecture restricts RAM allocation to $O(1)$. |
| **Zip Slip Path Traversal** | Canonical path validation prevents archives from writing outside designated targets. |
| **Magnetic Media Recovery** | DoD 5220.22-M 3-pass overwrite destroys residual physical magnetic charge. |

---

## 📖 Interview Preparation
For an in-depth breakdown of system design decisions, cryptographic mathematics, and top interview questions, see [INTERVIEW_GUIDE.md](file:///c:/Users/tarag/AES_/INTERVIEW_GUIDE.md).
