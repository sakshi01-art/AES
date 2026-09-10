<div align="center">

# 🔐 AES-256-GCM Cryptographic Suite

### <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=21&pause=1000&center=true&vCenter=true&width=720&lines=Authenticated+Encryption+%7C+Python;Learn+Cryptography+%E2%86%92+Build+Secure+Software;Confidentiality+%2B+Integrity+%F0%9F%94%90" alt="Typing animation" />

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![AES-GCM](https://img.shields.io/badge/AES--256--GCM-NIST%20SP%20800--38D-informational?style=for-the-badge)](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
[![Tests](https://img.shields.io/badge/Testing-Automated-success?style=for-the-badge&logo=pytest&logoColor=white)](#-testing)
[![Status](https://img.shields.io/badge/Status-Active%20Development-orange?style=for-the-badge)](#)

</div>

---

## ✨ Overview

A Python-based educational desktop application demonstrating **AES-256-GCM authenticated encryption**, secure file workflows, password/entropy concepts, and modular cryptographic software design.

> 🔒 **Built for learning secure software engineering—not for unauthorized access to data.**

## 🚀 Highlights

- 🔐 AES-256-GCM authenticated encryption
- 🧩 Password-based key derivation and secure randomness
- 📁 File and directory workflow support
- 📝 Secure message/notes demonstration
- 📊 Entropy and password-strength learning tools
- 🖥️ CustomTkinter desktop interface
- ⚡ Background task handling
- 🧪 Automated tests for core functionality

## 🏗️ Architecture

```text
              👤 User
                │
                ▼
        ┌─────────────────┐
        │   Desktop GUI   │
        └────────┬────────┘
                 ▼
        ┌─────────────────┐
        │ Application     │
        │     Layer       │
        └────────┬────────┘
          ┌──────┼──────┐
          ▼      ▼      ▼
       Crypto  Files  Entropy
       Engine  Tools  Utilities
          └──────┼──────┘
                 ▼
        🔐 AES-256-GCM
                 ▼
        📦 Encrypted Output
```

## 📂 Project Structure

```text
AES/
├── core/
│   ├── crypto_engine.py
│   ├── folder_processor.py
│   ├── password_manager.py
│   └── shredder.py
├── gui/
│   └── app.py
├── tests/
│   └── test_crypto.py
├── main.py
├── requirements.txt
├── INTERVIEW_GUIDE.md
└── README.md
```

## ⚙️ Installation

```bash
git clone https://github.com/sakshi01-art/AES.git
cd AES
python -m venv venv
```

### Windows

```bash
venv\Scripts\activate
```

### macOS / Linux

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

```bash
python -m unittest discover -s tests -v
```

## 🔒 Security Design

AES-GCM combines encryption with authentication, helping protect both confidentiality and integrity. The project also demonstrates cryptographically secure randomness and password-derived keys.

For real-world security systems, use established cryptographic libraries and obtain appropriate security review rather than relying on a learning project as a production security boundary.

## 🗺️ Roadmap

- [x] AES-256-GCM application foundation
- [x] Modular crypto and GUI architecture
- [x] Automated test foundation
- [x] Portfolio-quality documentation
- [ ] Expand test coverage
- [ ] Add CI checks
- [ ] Improve error handling and accessibility
- [ ] Add screenshots / demo GIF

## ⚠️ Responsible Use

This project is intended for **education, software development practice, and defensive security learning**. Use it only with data and systems you are authorized to work with.

## 👩‍💻 Author

**Sakshi Taragi**

[![GitHub](https://img.shields.io/badge/GitHub-sakshi01--art-181717?style=flat-square&logo=github)](https://github.com/sakshi01-art)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Sakshi%20Taragi-0A66C2?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/sakshi-taragi-6aa019435)

---

<div align="center">

⭐ **If this project helps you learn, consider starring it!**

<img src="https://capsule-render.vercel.app/api?type=waving&height=100&section=footer" alt="Animated footer" />

</div>
