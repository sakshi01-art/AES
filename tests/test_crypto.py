"""
Automated Cryptographic Verification Test Suite.
Validates roundtrip correctness, tamper detection, folder recursion,
entropy estimation, and file shredding.
"""
import os
import shutil
import tempfile
import unittest

from core.crypto_engine import AESCryptoEngine
from core.folder_processor import FolderProcessor
from core.shredder import FileShredder
from core.password_manager import PasswordManager


class TestAESCryptoSuite(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="aes_test_")
        self.password = "Secr3t_P@ssw0rd!2026"

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_text_encryption_roundtrip(self):
        """Validates that arbitrary unicode text encrypts and decrypts losslessly."""
        message = "Confidential Interview Document: AES-256-GCM Architecture 🚀"
        ciphertext = AESCryptoEngine.encrypt_text(message, self.password)
        self.assertIsInstance(ciphertext, str)
        self.assertNotEqual(message, ciphertext)

        decrypted = AESCryptoEngine.decrypt_text(ciphertext, self.password)
        self.assertEqual(message, decrypted)

    def test_text_tamper_detection(self):
        """Validates that tampering any byte in ciphertext raises ValueError."""
        message = "Top secret credentials"
        ciphertext = AESCryptoEngine.encrypt_text(message, self.password)

        # Tamper with the base64 string
        tampered_list = list(ciphertext)
        tampered_list[-5] = "A" if tampered_list[-5] != "A" else "B"
        tampered = "".join(tampered_list)

        with self.assertRaises(ValueError):
            AESCryptoEngine.decrypt_text(tampered, self.password)

    def test_file_encryption_roundtrip_with_integrity(self):
        """Validates file encryption, original filename recovery, and SHA-256 checksum."""
        original_file = os.path.join(self.test_dir, "sample_document.pdf")
        dummy_content = os.urandom(1024 * 512)  # 512 KB random payload
        with open(original_file, "wb") as f:
            f.write(dummy_content)

        enc_file = os.path.join(self.test_dir, "sample_document.pdf.aes")
        enc_res = AESCryptoEngine.encrypt_file_or_folder(original_file, enc_file, self.password)

        self.assertTrue(os.path.exists(enc_file))
        self.assertEqual(enc_res["status"], "success")

        # Decrypt into an isolated folder
        restore_dir = os.path.join(self.test_dir, "restored")
        os.makedirs(restore_dir, exist_ok=True)

        dec_res = AESCryptoEngine.decrypt_file(enc_file, output_dir=restore_dir, password=self.password)
        self.assertEqual(dec_res["status"], "success")
        self.assertEqual(dec_res["original_filename"], "sample_document.pdf")

        restored_file = dec_res["output_path"]
        self.assertTrue(os.path.exists(restored_file))

        with open(restored_file, "rb") as f:
            restored_content = f.read()

        self.assertEqual(dummy_content, restored_content)
        self.assertEqual(enc_res["sha256"], dec_res["sha256"])

    def test_file_tamper_rejection(self):
        """Validates that modified ciphertext causes GCM authentication failure and rolls back cleanly."""
        target_file = os.path.join(self.test_dir, "target.dat")
        with open(target_file, "wb") as f:
            f.write(b"Financial Transaction: Transfer $1,000,000 to Account X")

        enc_file = os.path.join(self.test_dir, "target.dat.aes")
        AESCryptoEngine.encrypt_file_or_folder(target_file, enc_file, self.password)

        # Flip a bit in the ciphertext portion
        with open(enc_file, "r+b") as f:
            f.seek(-20, os.SEEK_END)
            b = f.read(1)
            flipped = bytes([b[0] ^ 0x01])
            f.seek(-20, os.SEEK_END)
            f.write(flipped)

        restore_dir = os.path.join(self.test_dir, "tamper_out")
        with self.assertRaises(ValueError):
            AESCryptoEngine.decrypt_file(enc_file, output_dir=restore_dir, password=self.password)

        # Ensure no dirty/corrupted output file remains on disk
        dirty_file = os.path.join(restore_dir, "target.dat")
        self.assertFalse(os.path.exists(dirty_file))

    def test_folder_encryption_roundtrip(self):
        """Validates recursive folder packaging, encryption, decryption, and tree preservation."""
        project_dir = os.path.join(self.test_dir, "my_project_folder")
        os.makedirs(os.path.join(project_dir, "subfolder"), exist_ok=True)

        with open(os.path.join(project_dir, "file1.txt"), "w") as f:
            f.write("Root file contents")
        with open(os.path.join(project_dir, "subfolder", "nested.txt"), "w") as f:
            f.write("Nested file contents in subfolder")

        enc_vault = os.path.join(self.test_dir, "vault.aes")
        res = AESCryptoEngine.encrypt_file_or_folder(project_dir, enc_vault, self.password)
        self.assertTrue(res["is_directory"])

        restore_dir = os.path.join(self.test_dir, "extracted_tree")
        dec_res = AESCryptoEngine.decrypt_file(enc_vault, output_dir=restore_dir, password=self.password)
        self.assertTrue(dec_res["is_directory"])

        restored_folder = dec_res["output_path"]
        self.assertTrue(os.path.isdir(restored_folder))
        self.assertTrue(os.path.exists(os.path.join(restored_folder, "file1.txt")))
        self.assertTrue(os.path.exists(os.path.join(restored_folder, "subfolder", "nested.txt")))

        with open(os.path.join(restored_folder, "subfolder", "nested.txt"), "r") as f:
            self.assertEqual(f.read(), "Nested file contents in subfolder")

    def test_password_strength_and_entropy(self):
        """Validates password entropy calculation and CSPRNG password generation."""
        weak_eval = PasswordManager.evaluate_strength("12345")
        self.assertEqual(weak_eval["label"], "Very Weak")

        strong_eval = PasswordManager.evaluate_strength("Correct-Horse-Battery-Staple-2026!")
        self.assertIn(strong_eval["label"], ["Strong", "Very Strong"])

        generated = PasswordManager.generate_password(length=20)
        self.assertEqual(len(generated), 20)
        gen_eval = PasswordManager.evaluate_strength(generated)
        self.assertIn(gen_eval["label"], ["Strong", "Very Strong"])

    def test_dod_file_shredder(self):
        """Validates DoD 5220.22-M 3-pass file shredder securely wipes target."""
        shred_target = os.path.join(self.test_dir, "sensitive_to_destroy.key")
        with open(shred_target, "wb") as f:
            f.write(b"SUPER_SECRET_PRIVATE_KEY_BYTES_DO_NOT_RECOVER")

        self.assertTrue(os.path.exists(shred_target))
        shred_res = FileShredder.shred_file(shred_target, passes=3)
        self.assertTrue(shred_res)
        self.assertFalse(os.path.exists(shred_target))

    def test_legacy_v1_decryption(self):
        """Validates that files created with legacy V1 format decrypt seamlessly."""
        from Crypto.Cipher import AES
        import struct

        content = b"Legacy file data compatibility test"
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = AESCryptoEngine.derive_key(self.password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext = cipher.encrypt(content)
        tag = cipher.digest()

        v1_path = os.path.join(self.test_dir, "legacy.txt.aes")
        with open(v1_path, "wb") as f:
            f.write(b"AES256")
            f.write(struct.pack("B", 1))
            f.write(salt)
            f.write(nonce)
            f.write(ciphertext)
            f.write(tag)

        restore_dir = os.path.join(self.test_dir, "legacy_out")
        res = AESCryptoEngine.decrypt_file(v1_path, output_dir=restore_dir, password=self.password)
        self.assertEqual(res["status"], "success")

        with open(res["output_path"], "rb") as f:
            self.assertEqual(f.read(), content)


if __name__ == "__main__":
    unittest.main()
