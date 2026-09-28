import os
import tempfile
import unittest

from main import encrypt_file, decrypt_file


class TestAESFileCrypto(unittest.TestCase):
    def test_encrypt_decrypt_round_trip(self):
        password = "TestPassword123!"
        original = b"AES project integration test\n" * 20
        with tempfile.TemporaryDirectory() as tmp:
            source = os.path.join(tmp, "sample.txt")
            encrypted = os.path.join(tmp, "sample.txt.aes")
            restored = os.path.join(tmp, "sample_restored.txt")
            with open(source, "wb") as f:
                f.write(original)
            encrypt_file(source, encrypted, password)
            decrypt_file(encrypted, restored, password)
            with open(restored, "rb") as f:
                self.assertEqual(f.read(), original)

    def test_wrong_password_is_rejected_and_output_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = os.path.join(tmp, "sample.txt")
            encrypted = os.path.join(tmp, "sample.txt.aes")
            restored = os.path.join(tmp, "sample_restored.txt")
            with open(source, "wb") as f:
                f.write(b"secret test data")
            encrypt_file(source, encrypted, "CorrectPassword123!")
            with self.assertRaises(ValueError):
                decrypt_file(encrypted, restored, "WrongPassword123!")
            self.assertFalse(os.path.exists(restored))

    def test_empty_file_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = os.path.join(tmp, "empty.txt")
            encrypted = os.path.join(tmp, "empty.txt.aes")
            restored = os.path.join(tmp, "empty_restored.txt")
            open(source, "wb").close()
            encrypt_file(source, encrypted, "EmptyFilePass123!")
            decrypt_file(encrypted, restored, "EmptyFilePass123!")
            self.assertEqual(os.path.getsize(restored), 0)

    def test_tamper_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = os.path.join(tmp, "sample.txt")
            encrypted = os.path.join(tmp, "sample.txt.aes")
            restored = os.path.join(tmp, "sample_restored.txt")
            with open(source, "wb") as f:
                f.write(b"authenticated data")
            encrypt_file(source, encrypted, "TamperTest123!")
            with open(encrypted, "r+b") as f:
                f.seek(-1, os.SEEK_END)
                last = f.read(1)
                f.seek(-1, os.SEEK_END)
                f.write(bytes([last[0] ^ 1]))
            with self.assertRaises(ValueError):
                decrypt_file(encrypted, restored, "TamperTest123!")
            self.assertFalse(os.path.exists(restored))


if __name__ == "__main__":
    unittest.main()
