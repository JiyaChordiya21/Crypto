import os
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

# Constants
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32
ITERATIONS = 200_000

# Crypto functions
def derive_key(password, salt):
    return PBKDF2(password.encode(), salt, dkLen=KEY_SIZE, count=ITERATIONS, hmac_hash_module=SHA256)

def encrypt_file(file_path, password):
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    with open(file_path, "rb") as f:
        plaintext = f.read()

    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    output_path = file_path + ".enc"

    with open(output_path, "wb") as f:
        f.write(salt + nonce + tag + ciphertext)

    return output_path

def decrypt_file(file_path, password, save_path):
    with open(file_path, "rb") as f:
        data = f.read()

    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    tag = data[SALT_SIZE + NONCE_SIZE:SALT_SIZE + NONCE_SIZE + TAG_SIZE]
    ciphertext = data[SALT_SIZE + NONCE_SIZE + TAG_SIZE:]

    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except Exception as e:
        return False, str(e)

    with open(save_path, "wb") as f:
        f.write(plaintext)
    return True, save_path

# GUI
class FileEncryptorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Encryptor (AES-GCM)")
        self.root.geometry("560x160")
        self.file_path = tk.StringVar()

        tk.Label(root, text="File to Encrypt/Decrypt:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        tk.Entry(root, textvariable=self.file_path, width=50).grid(row=0, column=1)
        tk.Button(root, text="Browse", command=self.browse_file).grid(row=0, column=2)

        tk.Label(root, text="Password:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.password_entry = tk.Entry(root, show="*", width=40)
        self.password_entry.grid(row=1, column=1, pady=5)

        tk.Button(root, text="Encrypt File", command=self.encrypt_action, width=20).grid(row=2, column=0, padx=10, pady=10)
        tk.Button(root, text="Decrypt File", command=self.decrypt_action, width=20).grid(row=2, column=1, padx=5, pady=10, sticky="w")

    def browse_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_path.set(path)

    def encrypt_action(self):
        path = self.file_path.get()
        password = self.password_entry.get()

        if not path or not password:
            messagebox.showerror("Missing Info", "Please select a file and enter a password.")
            return

        try:
            out_path = encrypt_file(path, password)
            messagebox.showinfo("Success", f"Encrypted file saved as:\n{out_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed:\n{str(e)}")

    def decrypt_action(self):
        path = self.file_path.get()
        password = self.password_entry.get()

        if not path.endswith(".enc"):
            messagebox.showerror("Invalid File", "Please select a .enc encrypted file.")
            return

        if not path or not password:
            messagebox.showerror("Missing Info", "Please select a file and enter a password.")
            return

        save_path = filedialog.asksaveasfilename(title="Save Decrypted File As")
        if not save_path:
            return

        success, result = decrypt_file(path, password, save_path)
        if success:
            messagebox.showinfo("Success", f"Decrypted file saved as:\n{result}")
        else:
            messagebox.showerror("Failed", f"Decryption failed:\n{result}")

# Run GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptorGUI(root)
    root.mainloop()
