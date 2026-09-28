"""AES-256-GCM file encryption/decryption desktop application.

This entry point is intentionally self-contained so the project can be
installed and launched without the older GUI package tree.
"""
import os
import struct
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32
CHUNK_SIZE = 1024 * 1024
PBKDF2_ITERATIONS = 200_000
MAGIC = b"AES256"
VERSION = 1


def derive_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("Password cannot be empty.")
    return PBKDF2(
        password.encode("utf-8"),
        salt,
        dkLen=KEY_SIZE,
        count=PBKDF2_ITERATIONS,
        hmac_hash_module=SHA256,
    )


def encrypt_file(input_file, output_file, password, progress_callback=None):
    if not os.path.isfile(input_file):
        raise FileNotFoundError("Input file was not found.")
    if os.path.abspath(input_file) == os.path.abspath(output_file):
        raise ValueError("Input and output files must be different.")

    file_size = os.path.getsize(input_file)
    salt = get_random_bytes(SALT_SIZE)
    nonce = get_random_bytes(NONCE_SIZE)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    try:
        with open(input_file, "rb") as source, open(output_file, "wb") as destination:
            destination.write(MAGIC + struct.pack("B", VERSION) + salt + nonce)
            processed = 0
            while True:
                chunk = source.read(CHUNK_SIZE)
                if not chunk:
                    break
                destination.write(cipher.encrypt(chunk))
                processed += len(chunk)
                if progress_callback:
                    progress_callback(100 if file_size == 0 else processed / file_size * 100)
            destination.write(cipher.digest())
    except Exception:
        if os.path.exists(output_file):
            os.remove(output_file)
        raise

    if progress_callback:
        progress_callback(100)


def decrypt_file(input_file, output_file, password, progress_callback=None):
    if not os.path.isfile(input_file):
        raise FileNotFoundError("Encrypted file was not found.")
    if os.path.abspath(input_file) == os.path.abspath(output_file):
        raise ValueError("Input and output files must be different.")

    file_size = os.path.getsize(input_file)
    header_size = len(MAGIC) + 1 + SALT_SIZE + NONCE_SIZE
    minimum_size = header_size + TAG_SIZE
    if file_size < minimum_size:
        raise ValueError("Invalid encrypted file.")

    try:
        with open(input_file, "rb") as source:
            if source.read(len(MAGIC)) != MAGIC:
                raise ValueError("Invalid AES file format.")

            version_raw = source.read(1)
            if len(version_raw) != 1 or struct.unpack("B", version_raw)[0] != VERSION:
                raise ValueError("Unsupported file version.")

            salt = source.read(SALT_SIZE)
            nonce = source.read(NONCE_SIZE)
            ciphertext_size = file_size - header_size - TAG_SIZE
            key = derive_key(password, salt)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

            os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
            with open(output_file, "wb") as destination:
                processed = 0
                remaining = ciphertext_size
                while remaining:
                    read_size = min(CHUNK_SIZE, remaining)
                    chunk = source.read(read_size)
                    if len(chunk) != read_size:
                        raise ValueError("Encrypted file is corrupted.")
                    destination.write(cipher.decrypt(chunk))
                    processed += len(chunk)
                    remaining -= len(chunk)
                    if progress_callback:
                        progress_callback(100 if ciphertext_size == 0 else processed / ciphertext_size * 100)

                tag = source.read(TAG_SIZE)
                if len(tag) != TAG_SIZE:
                    raise ValueError("Authentication tag missing.")
                cipher.verify(tag)
    except ValueError:
        if os.path.exists(output_file):
            os.remove(output_file)
        raise
    except Exception:
        if os.path.exists(output_file):
            os.remove(output_file)
        raise

    if progress_callback:
        progress_callback(100)


class AESFileApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES-256 File Security")
        self.root.geometry("760x560")
        self.root.resizable(False, False)
        self.root.configure(bg="#101820")
        self.selected_file = ""
        self._build_ui()

    def _build_ui(self):
        header = tk.Frame(self.root, bg="#16232E", height=110)
        header.pack(fill="x")
        tk.Label(header, text="AES-256 FILE SECURITY", font=("Segoe UI", 25, "bold"),
                 fg="white", bg="#16232E").pack(pady=(22, 3))
        tk.Label(header, text="Authenticated File Encryption & Decryption",
                 font=("Segoe UI", 11), fg="#B8C7D1", bg="#16232E").pack()

        main = tk.Frame(self.root, bg="#101820")
        main.pack(fill="both", expand=True, padx=55, pady=25)

        tk.Label(main, text="Select File", font=("Segoe UI", 13, "bold"),
                 fg="white", bg="#101820").pack(anchor="w")
        file_frame = tk.Frame(main, bg="#1C2B36", padx=15, pady=12)
        file_frame.pack(fill="x", pady=(8, 20))
        self.file_label = tk.Label(file_frame, text="No file selected", font=("Segoe UI", 11),
                                   fg="#D9E2E8", bg="#1C2B36", anchor="w")
        self.file_label.pack(side="left", fill="x", expand=True)
        ttk.Button(file_frame, text="Browse", command=self.select_file).pack(side="right")

        tk.Label(main, text="Password", font=("Segoe UI", 13, "bold"),
                 fg="white", bg="#101820").pack(anchor="w")
        self.password_entry = tk.Entry(main, show="*", font=("Segoe UI", 12), relief="flat")
        self.password_entry.pack(fill="x", ipady=8, pady=(8, 12))

        tk.Label(main, text="Confirm Password (encryption only)",
                 font=("Segoe UI", 13, "bold"), fg="white", bg="#101820").pack(anchor="w")
        self.confirm_entry = tk.Entry(main, show="*", font=("Segoe UI", 12), relief="flat")
        self.confirm_entry.pack(fill="x", ipady=8, pady=(8, 20))

        button_frame = tk.Frame(main, bg="#101820")
        button_frame.pack(pady=5)
        for label, command, bg in [
            ("🔒 Encrypt", self.encrypt_button, "#1976D2"),
            ("🔓 Decrypt", self.decrypt_button, "#388E3C"),
            ("Clear", self.clear, "#455A64"),
        ]:
            tk.Button(button_frame, text=label, command=command, font=("Segoe UI", 11, "bold"),
                      bg=bg, fg="white", relief="flat", padx=28, pady=10,
                      cursor="hand2").pack(side="left", padx=8)

        self.progress = ttk.Progressbar(main, orient="horizontal", length=600, mode="determinate")
        self.progress.pack(pady=(25, 8))
        self.progress_label = tk.Label(main, text="0%", font=("Segoe UI", 10),
                                       fg="#B8C7D1", bg="#101820")
        self.progress_label.pack()

        self.status_label = tk.Label(self.root, text="Ready", font=("Segoe UI", 10),
                                     fg="#B8C7D1", bg="#101820")
        self.status_label.pack(pady=(0, 15))

    def select_file(self):
        path = filedialog.askopenfilename(title="Select File")
        if path:
            self.selected_file = path
            self.file_label.config(text=os.path.basename(path))
            self.status_label.config(text="File selected.")

    def get_password(self, require_confirmation=True):
        password = self.password_entry.get()
        confirm = self.confirm_entry.get()
        if not password:
            messagebox.showwarning("Password Required", "Please enter a password.")
            return None
        if len(password) < 8:
            messagebox.showwarning("Weak Password", "Password must contain at least 8 characters.")
            return None
        if require_confirmation and password != confirm:
            messagebox.showwarning("Password Mismatch", "Passwords do not match.")
            return None
        return password

    def update_progress(self, value):
        self.progress["value"] = value
        self.progress_label.config(text=f"{value:.1f}%")
        self.root.update_idletasks()

    def encrypt_button(self):
        if not self.selected_file:
            messagebox.showwarning("No File", "Please select a file first.")
            return
        password = self.get_password(True)
        if password is None:
            return
        output_file = self.selected_file + ".aes"
        try:
            self.status_label.config(text="Encrypting...")
            self.progress["value"] = 0
            encrypt_file(self.selected_file, output_file, password, self.update_progress)
            self.status_label.config(text="Encryption completed successfully.")
            messagebox.showinfo("Success", f"File encrypted successfully.\n\nSaved as:\n{output_file}")
        except Exception as error:
            self.status_label.config(text="Encryption failed.")
            messagebox.showerror("Encryption Error", str(error))

    def decrypt_button(self):
        if not self.selected_file:
            messagebox.showwarning("No File", "Please select a file first.")
            return
        if not self.selected_file.lower().endswith(".aes"):
            messagebox.showwarning("Invalid File", "Please select a .aes encrypted file.")
            return
        password = self.get_password(False)
        if password is None:
            return
        output_file = self.selected_file[:-4] + "_decrypted"
        if os.path.exists(output_file) and not messagebox.askyesno(
            "File Already Exists", f"{os.path.basename(output_file)} already exists. Replace it?"
        ):
            return
        try:
            self.status_label.config(text="Decrypting...")
            self.progress["value"] = 0
            decrypt_file(self.selected_file, output_file, password, self.update_progress)
            self.status_label.config(text="Decryption completed successfully.")
            messagebox.showinfo("Success", f"File decrypted successfully.\n\nSaved as:\n{output_file}")
        except Exception as error:
            self.status_label.config(text="Decryption failed.")
            messagebox.showerror("Decryption Failed", str(error))

    def clear(self):
        self.selected_file = ""
        self.file_label.config(text="No file selected")
        self.password_entry.delete(0, tk.END)
        self.confirm_entry.delete(0, tk.END)
        self.progress["value"] = 0
        self.progress_label.config(text="0%")
        self.status_label.config(text="Ready")


def main():
    root = tk.Tk()
    AESFileApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
