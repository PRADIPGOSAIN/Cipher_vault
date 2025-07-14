# 🔐 God-Level Secure Password Vault (Open Source)

This is a **highly secure password vault** built in Python by **Pradip Gosain**, featuring AES-256 encryption, strong password protection, and modern security practices.

---

## 🚀 Features

- AES-256-GCM encryption (authenticated)
- Master password (PBKDF2 with 600,000 iterations)
- Clipboard auto-clear (after 10 seconds)
- Password strength checking using zxcvbn
- Fully encrypted offline vault (stored locally)
- Easy vault backup and master password change

---

## 📦 Installation

```bash
git clone https://github.com/pradipgosain/god-level-password-vault.git
cd god-level-password-vault
pip install -r requirements.txt
python vault.py
