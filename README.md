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
🛡️ Security Notes
Your vault is encrypted using AES-GCM (256-bit key)

Passwords are never stored in plaintext

Your master password never leaves your device

Clipboard auto-clears after use

⚠️ License & Usage
This project is licensed under the GNU AGPL-3.0 License.

✅ You can:

Use it for free

Study, modify, or share it

Use it in personal or research projects

❌ You CANNOT:

Sell it as your own

Remove the creator’s credit

Use it in a closed-source or commercial product without permission

If you use this vault, give credit to Pradip Gosain. ❤️

👨‍💻 Creator
Pradip Gosain
🔗 GitHub: github.com/pradipgosain

## 📦 Installation

```bash
git clone https://github.com/pradipgosain/god-level-password-vault.git
cd god-level-password-vault
pip install -r requirements.txt
python vault.py
