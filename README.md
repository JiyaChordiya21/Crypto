# 🔐 SecureCryptor

A simple and secure file encryption/decryption tool with a clean GUI, built in Python using AES-256-GCM. Designed to protect sensitive files using strong password-based encryption with zero data loss — even for binary files like `.docx`, `.pdf`, and `.jpg`.

---

## 🧰 Features

- 🔒 AES-256 GCM encryption (authenticated encryption)
- 🔐 Password-based key derivation (PBKDF2 with SHA-256)
- 🖼 Simple and intuitive Tkinter GUI
- 🧾 Handles all file types (text, binary, documents, images, etc.)
- 🔓 Secure decryption with output control
- ✅ Cross-platform (Linux, Windows, macOS)

### 📦 Requirements

- Python 3.8+
- PyCryptodome
- Tkinter (included with Python)

Install dependencies:

```bash
pip install pycryptodome
````

---

## 💻 Usage

### 🟢 Run the GUI

```bash
python secure_file_gui.py
```

### 🔐 Encrypting a File

1. Click **Browse** and select any file.
2. Enter a strong password.
3. Click **Encrypt File** → it will save `filename.ext.enc`.

### 🔓 Decrypting a File

1. Select a `.enc` file.
2. Enter the password used during encryption.
3. Click **Decrypt File**.
4. Choose where to save the decrypted output.

---

## 📂 File Structure

```
.
├── secure_file_gui.py        # Main GUI application
├── README.md
├── LICENSE
└── /tests                    # Optional test scripts
```

---

## 🔐 How It Works

* Uses AES in GCM mode for confidentiality + integrity
* Random salt and nonce generated per file
* Passwords are converted to 256-bit keys using PBKDF2
* Decryption validates tag before writing output



## 🛡️ Security Notes

* Your password is **never stored** or logged
* File format: `[salt][nonce][tag][ciphertext]`
* One-time nonce + salt ensures every encryption is unique



## 📝 License

MIT License © 2025 JiyaChordiya


## 🙋‍♂️ Want More?

* 🔄 Add zip+encrypt folder support
* 🧠 Add SHA-256 hash check before/after
* 🌐 Add CLI mode (optional)


