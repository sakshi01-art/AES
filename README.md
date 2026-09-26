<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&height=180&section=header&text=AES-256-GCM&fontSize=46&fontAlignY=35&desc=Authenticated%20Encryption%20%7C%20Python%20%7C%20Secure%20Software&descAlignY=60&animation=fadeIn" width="100%" alt="AES animated banner" />

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=21&pause=850&center=true&vCenter=true&width=780&lines=Confidentiality+%2B+Integrity+%F0%9F%94%90;Learn+Cryptography+%E2%86%92+Build+Secure+Software;Python+%7C+AES-GCM+%7C+Security+Learning" alt="Typing animation" />

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![AES-GCM](https://img.shields.io/badge/AES--256--GCM-NIST%20SP%20800--38D-2563EB?style=for-the-badge)](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
[![Tests](https://img.shields.io/badge/Testing-Automated-16A34A?style=for-the-badge&logo=pytest&logoColor=white)](#-testing)
[![Status](https://img.shields.io/badge/Status-Active%20Development-F59E0B?style=for-the-badge)](#)

</div>

---

## 🔐 Overview

A Python-based educational project demonstrating **AES-256-GCM authenticated encryption**, secure software design concepts, password/key handling, and modular application architecture.

> 🧠 **Learn cryptography by understanding the design—not by reinventing production security.**

## 🎨 Project Visual

<p align="center">
  <img src="./assets/project-draw.svg" alt="AES-256-GCM secure software architecture" width="100%" />
</p>

> **Visual:** User/GUI → application layer → crypto engine → authenticated output.

---

## ✨ Highlights

| 🔐 | Capability | Purpose |
|---|---|---|
| 🛡️ | AES-256-GCM | Authenticated encryption concepts |
| 🧩 | Key Handling | Password-derived key learning |
| 🎲 | Secure Randomness | Cryptographic randomness concepts |
| 🖥️ | Desktop UI | Application-oriented learning |
| 🧪 | Testing | Validate core functionality |
| 📚 | Documentation | Understand the security design |

## 🏗️ Architecture

```text
             👤 USER
                │
                ▼
        ┌───────────────┐
        │  Desktop GUI  │
        └───────┬───────┘
                ▼
        ┌───────────────┐
        │ Application   │
        │     Layer     │
        └───────┬───────┘
          ┌─────┼─────┐
          ▼     ▼     ▼
       🔐 Crypto  📁 Files  📊 Utilities
          │     │     │
          └─────┼─────┘
                ▼
          AES-256-GCM
                │
                ▼
        🔒 Authenticated Output
```

## 🛠️ Technology Stack

<p align="center">
<img src="https://skillicons.dev/icons?i=python,git,github,vscode" alt="Technology icons" />
</p>

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

Install dependencies:

```bash
pip install -r requirements.txt
```

## 🧪 Testing

```bash
python -m unittest discover -s tests -v
```

## 🗺️ Roadmap

- [x] AES-256-GCM application foundation
- [x] Modular documentation
- [x] Automated test foundation
- [x] Animated project presentation
- [ ] Expand test coverage
- [ ] Add CI checks
- [ ] Improve accessibility and error handling
- [ ] Add screenshots / demo GIF

## 🔒 Security Notes

AES-GCM provides confidentiality and integrity when used correctly. Production systems should rely on well-reviewed cryptographic libraries, safe key management, secure nonce handling, and professional security review.

This repository is a **learning project**, not a replacement for production security engineering.

## ⚠️ Responsible Use

Use this project only with data and systems you are authorized to work with.

## 👩‍💻 Author

**Sakshi Taragi**

[![GitHub](https://img.shields.io/badge/GitHub-sakshi01--art-181717?style=flat-square&logo=github)](https://github.com/sakshi01-art)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Sakshi%20Taragi-0A66C2?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/sakshi-taragi-6aa019435)

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&height=110&section=footer&animation=twinkling" width="100%" alt="Animated footer" />

⭐ **Learn secure. Build smart.** 🔐

</div>


---

## 🔥 Latest Update — 20 September 2026

- Refreshed the project documentation and presentation.
- Kept the architecture and development roadmap clear for future modules.
- Continuing practical implementation and incremental improvements.


## 🔥 Latest Update — 22 September 2026

- Added AES-256-GCM design notes under `docs/`.
- Documented confidentiality, authentication, nonce handling, and testing priorities.
- Continued the project as an educational secure-software implementation.

## 🚀 Development Update — 22 September 2026

- Clarified the educational focus on authenticated encryption and secure software design.
- Highlighted testing, error handling, and safe key/nonce practices as the next development areas.
- Kept production-security limitations clearly documented.

---

## 🚀 Development Update — 24 September 2026

- Refined the authenticated-encryption learning roadmap.
- Added clearer checkpoints for input validation, error handling, testing, and secure configuration.
- Kept the implementation focused on learning AES-GCM concepts without presenting it as production security software.

---

## ✨ Development Update — 26 September 2026

- Refreshed the project documentation for the latest development stage.
- Kept the roadmap focused on practical implementation, testing, and continuous improvement.
- Updated the project progress section so the repository stays current and easy to review.
