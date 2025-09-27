# Ravicrypto - Image Encryption Tool 🛡️

A simple Python tool to encrypt and decrypt images using **AES-256-CBC** or **Triple DES (3DES)**.

## 🔐 Features
- AES and 3DES encryption
- Secure password-based key derivation (PBKDF2)
- Salt and IV generation for each file
- CLI interface for encryption and decryption

## 🧪 Usage

### Encrypt:
```bash
python ravicrypto_file.py encrypt image.jpg image.enc --password "yourpass" --algo AES
