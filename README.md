# 🔐 God-Level Secure Password Vault (Open Source)

A **highly secure password vault** built in Python by **Pradip Gosain**, featuring **AES-256-GCM encryption**, a strong master password system, and modern, uncompromising security practices.

---

## 🚀 Features

- ✅ **AES-256-GCM Encryption** – Secure, authenticated encryption
- ✅ **Master Password Protection** – Uses PBKDF2 (600,000 iterations)
- ✅ **Clipboard Auto-Clear** – Passwords auto-clear from clipboard after 10 seconds
- ✅ **Password Strength Checking** – Integrated [zxcvbn](https://github.com/dropbox/zxcvbn) support
- ✅ **Fully Encrypted Offline Vault** – Stored locally, no internet required
- ✅ **Master Password Change & Backup** – Easy vault recovery and update

---

## 🛡️ Security Notes

- 🔐 Vault encrypted using **AES-GCM with a 256-bit key**
- 🔐 **No plaintext passwords** are ever stored
- 🔐 **Master password never leaves your device**
- 🔐 **Clipboard data is auto-cleared** after 10 seconds to prevent leakage

---

## ⚠️ License & Usage

This project is licensed under the **GNU AGPL-3.0 License**.

### ✅ You Can:
- Use it for free
- Study, modify, or share it
- Use it in personal or research projects

### ❌ You Cannot:
- Sell it as your own
- Remove the creator’s credit
- Use it in a closed-source or commercial product without permission

> If you use this vault, **give credit to Pradip Gosain**. ❤️

---

## 👨‍💻 Creator

**Pradip Gosain**  
🔗 GitHub: [github.com/pradipgosain](https://github.com/pradipgosain)

---

## 📦 Installation

```bash
git clone https://github.com/pradipgosain/god-level-password-vault.git
cd god-level-password-vault
pip install -r requirements.txt
python ciphervaultpro.py
