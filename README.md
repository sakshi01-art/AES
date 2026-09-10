# 🔐 AES-256-GCM Cryptographic Suite

> A Python-based educational desktop application for learning authenticated encryption, secure file handling, and cryptographic engineering concepts.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Cipher](https://img.shields.io/badge/Cipher-AES--256--GCM-4c8.svg)](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
[![Status](https://img.shields.io/badge/Status-Active%20Development-success.svg)]()

## ✨ Overview

AES is a symmetric-key block cipher. This project demonstrates how **AES-256-GCM** can be used to provide confidentiality and integrity together with authenticated encryption.

The application is designed as a portfolio and learning project, with a desktop interface and modular Python components.

## 🚀 Highlights

- 🔐 AES-256-GCM authenticated encryption
- 🧩 Password-based key derivation and cryptographic randomness
- 📁 File and directory workflow support
- 📝 Secure message/notes demonstration
- 📊 Entropy and password-strength learning tools
- 🖥️ Desktop GUI built with CustomTkinter
- ⚡ Background task handling for a responsive interface
- 🧪 Automated tests for core functionality

## 🏗️ Architecture

```text
User
  │
  ▼
Desktop GUI
  │
  ▼
Application Layer
  │
  ├── Crypto Engine
  ├── File/Folder Processing
  └── Password & Entropy Utilities
  │
  ▼
Authenticated Encryption
  │
  ▼
Encrypted Output
```

## 📂 Project Structure

```text
AES/
├── core/
│   ├── __init__.py
│   ├── crypto_engine.py
│   ├── folder_processor.py
│   ├── password_manager.py
│   └── shredder.py
├── gui/
│   ├── __init__.py
│   └── app.py
├── tests/
│   ├── __init__.py
│   └── test_crypto.py
├── main.py
├── requirements.txt
├── INTERVIEW_GUIDE.md
└── README.md
```

## ⚙️ Installation

### Requirements

- Python 3.10 or newer
- A supported desktop environment

### Setup

```bash
git clone https://github.com/sakshi01-art/AES.git
cd AES
python -m venv venv
```

Windows:

```bash
venv\Scripts\activate
```

macOS/Linux:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## ▶️ Run

```bash
python main.py
```

## 🧪 Testing

Run the automated test suite with:

```bash
python -m unittest discover -s tests -v
```

## 🔒 Security Design

The project focuses on authenticated encryption and safe cryptographic engineering practices. AES-GCM provides both confidentiality and integrity authentication, while cryptographically secure randomness is used for security-sensitive values.

For production systems, use well-maintained cryptographic libraries and have security-sensitive implementations reviewed by qualified professionals.

## 🗺️ Roadmap

- [x] AES-256-GCM application foundation
- [x] Modular crypto and GUI architecture
- [x] Automated test foundation
- [ ] Expand test coverage
- [ ] Improve documentation and diagrams
- [ ] Add CI checks
- [ ] Add clearer error handling and user feedback
- [ ] Improve accessibility and cross-platform support

## ⚠️ Disclaimer

This project is intended for **education, software development practice, and defensive security learning**. Do not use it to access, modify, or protect data without appropriate authorization.

## 👩‍💻 Author

**Sakshi Taragi**

- GitHub: https://github.com/sakshi01-art
- LinkedIn: https://www.linkedin.com/in/sakshi-taragi-6aa019435

⭐ If you find this project useful for learning, consider starring the repository.