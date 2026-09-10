"""
Cryptographic Engine Subsystem implementing AES-256-GCM authenticated streaming encryption.
Complies with NIST SP 800-38D, OWASP Key Derivation Standards, and O(1) Memory Streaming.
"""
import base64
import hashlib
import json
import os
import struct
import threading
import time
from typing import Callable, Optional, Dict, Any, Tuple

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

from .folder_processor import FolderProcessor


class AESCryptoEngine:
    """
    Production-grade AES-256-GCM Streaming Cryptographic Engine.
    Features:
      - Authenticated Encryption with Associated Data (AEAD)
      - O(1) Memory Streaming (1MB chunks)
      - Embedded Encrypted Authenticated Metadata (Filename, Hash, Type)
      - PBKDF2-HMAC-SHA256 (250,000 iterations)
      - Bit-Level Integrity Validation via Dual Verification (GCM Tag + SHA-256)
      - Legacy V1 Format Backward-Compatibility
      - Cancelable background operations with safe rollback
    """

    MAGIC_V2 = b"AESGCM"
    MAGIC_V1 = b"AES256"
    CURRENT_VERSION = 2

    SALT_SIZE = 16          # 128-bit Salt
    NONCE_SIZE = 12         # 96-bit Nonce (Standard for GCM per NIST SP 800-38D)
    TAG_SIZE = 16           # 128-bit Authentication Tag
    KEY_SIZE = 32           # 256-bit AES Key
    CHUNK_SIZE = 1024 * 1024  # 1 MB Streaming Buffer
    PBKDF2_ROUNDS = 250000  # OWASP Brute-Force Deterrent Standard

    @classmethod
    def derive_key(cls, password: str, salt: bytes) -> bytes:
        """
        Derives a 256-bit symmetric key using PBKDF2-HMAC-SHA256 with 250,000 iterations.
        """
        return PBKDF2(
            password.encode("utf-8"),
            salt,
            dkLen=cls.KEY_SIZE,
            count=cls.PBKDF2_ROUNDS,
            hmac_hash_module=SHA256
        )

    @classmethod
    def calculate_file_hash(cls, file_path: str) -> str:
        """
        Computes SHA-256 checksum of an existing file using chunked streaming.
        """
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(cls.CHUNK_SIZE):
                hasher.update(chunk)
        return hasher.hexdigest()

    @classmethod
    def encrypt_file_or_folder(
        cls,
        source_path: str,
        output_file: str,
        password: str,
        progress_callback: Optional[Callable[[float, str, str], None]] = None,
        cancel_event: Optional[threading.Event] = None
    ) -> Dict[str, Any]:
        """
        Encrypts a single file or an entire directory tree using AES-256-GCM.
        Saves metadata (original name, hash, is_folder) within authenticated stream.
        """
        is_directory = os.path.isdir(source_path)
        temp_archive_path = None

        if is_directory:
            # Package directory into secure temporary zip archive
            temp_archive_path = output_file + ".tmp_pack"
            FolderProcessor.pack_directory(source_path, temp_archive_path)
            input_file = temp_archive_path
            original_filename = os.path.basename(os.path.normpath(source_path))
        else:
            input_file = source_path
            original_filename = os.path.basename(source_path)

        try:
            total_size = os.path.getsize(input_file)
            sha256_original = cls.calculate_file_hash(input_file)

            salt = get_random_bytes(cls.SALT_SIZE)
            nonce = get_random_bytes(cls.NONCE_SIZE)
            key = cls.derive_key(password, salt)

            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

            # Prepare metadata packet
            metadata = {
                "version": cls.CURRENT_VERSION,
                "filename": original_filename,
                "orig_size": total_size,
                "is_directory": is_directory,
                "sha256": sha256_original,
                "timestamp": int(time.time())
            }
            metadata_bytes = json.dumps(metadata).encode("utf-8")
            meta_len_header = struct.pack(">I", len(metadata_bytes))

            # Encrypt metadata first
            encrypted_meta = cipher.encrypt(meta_len_header + metadata_bytes)

            start_time = time.time()
            processed_bytes = 0

            with open(input_file, "rb") as src, open(output_file, "wb") as dst:
                # Write outer unencrypted header: MAGIC + VERSION + SALT + NONCE + META_BLOCK_LEN
                dst.write(cls.MAGIC_V2)
                dst.write(struct.pack("B", cls.CURRENT_VERSION))
                dst.write(salt)
                dst.write(nonce)
                # Length of encrypted metadata block
                dst.write(struct.pack(">I", len(encrypted_meta)))
                dst.write(encrypted_meta)

                while True:
                    if cancel_event and cancel_event.is_set():
                        raise InterruptedError("Operation canceled by user.")

                    chunk = src.read(cls.CHUNK_SIZE)
                    if not chunk:
                        break

                    enc_chunk = cipher.encrypt(chunk)
                    dst.write(enc_chunk)

                    processed_bytes += len(chunk)
                    elapsed = max(0.001, time.time() - start_time)
                    speed_mbps = (processed_bytes / (1024 * 1024)) / elapsed
                    remaining_bytes = max(0, total_size - processed_bytes)
                    eta_sec = remaining_bytes / max(1.0, (processed_bytes / elapsed))

                    if progress_callback:
                        pct = (processed_bytes / max(1, total_size)) * 100
                        speed_str = f"{speed_mbps:.1f} MB/s"
                        eta_str = f"{int(eta_sec)}s left" if eta_sec < 3600 else "> 1h"
                        progress_callback(pct, speed_str, eta_str)

                # Append final 128-bit authentication tag
                tag = cipher.digest()
                dst.write(tag)

            if progress_callback:
                progress_callback(100.0, "Completed", "0s")

            return {
                "status": "success",
                "output_file": output_file,
                "sha256": sha256_original,
                "is_directory": is_directory,
                "original_filename": original_filename,
                "file_size": total_size
            }

        except Exception as err:
            # Clean up partial encrypted file on failure or cancellation
            if os.path.exists(output_file):
                try:
                    os.remove(output_file)
                except OSError:
                    pass
            raise err

        finally:
            # Clean up temporary archive if folder was processed
            if temp_archive_path and os.path.exists(temp_archive_path):
                try:
                    os.remove(temp_archive_path)
                except OSError:
                    pass

    @classmethod
    def decrypt_file(
        cls,
        encrypted_file: str,
        output_dir: Optional[str] = None,
        password: str = "",
        progress_callback: Optional[Callable[[float, str, str], None]] = None,
        cancel_event: Optional[threading.Event] = None
    ) -> Dict[str, Any]:
        """
        Decrypts an AES-256 encrypted file. Supports V2 (with metadata & folder recovery)
        as well as legacy V1 format.
        """
        if not os.path.exists(encrypted_file):
            raise FileNotFoundError(f"File not found: {encrypted_file}")

        file_size = os.path.getsize(encrypted_file)
        target_dir = output_dir or os.path.dirname(encrypted_file)
        if target_dir:
            os.makedirs(target_dir, exist_ok=True)

        with open(encrypted_file, "rb") as src:
            # Inspect magic signature
            magic_candidate = src.read(6)
            if magic_candidate == cls.MAGIC_V2:
                version = struct.unpack("B", src.read(1))[0]
                if version != 2:
                    raise ValueError(f"Unsupported specification version: {version}")
                return cls._decrypt_v2(src, file_size, encrypted_file, target_dir, password, progress_callback, cancel_event)
            elif magic_candidate == cls.MAGIC_V1:
                # Legacy V1
                version = struct.unpack("B", src.read(1))[0]
                if version != 1:
                    raise ValueError(f"Unsupported legacy specification version: {version}")
                return cls._decrypt_v1(src, file_size, encrypted_file, target_dir, password, progress_callback, cancel_event)
            else:
                raise ValueError("Invalid file format. Header does not match AES-256 signature.")

    @classmethod
    def _decrypt_v2(
        cls,
        src,
        total_file_size: int,
        encrypted_file: str,
        target_dir: str,
        password: str,
        progress_callback: Optional[Callable[[float, str, str], None]],
        cancel_event: Optional[threading.Event]
    ) -> Dict[str, Any]:
        salt = src.read(cls.SALT_SIZE)
        nonce = src.read(cls.NONCE_SIZE)
        meta_block_len = struct.unpack(">I", src.read(4))[0]
        encrypted_meta = src.read(meta_block_len)

        key = cls.derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        # Decrypt metadata header
        try:
            decrypted_meta_raw = cipher.decrypt(encrypted_meta)
            meta_json_len = struct.unpack(">I", decrypted_meta_raw[:4])[0]
            metadata = json.loads(decrypted_meta_raw[4:4 + meta_json_len].decode("utf-8"))
        except Exception:
            raise ValueError("Decryption failed: Authentication tag failure or incorrect password.")

        is_directory = metadata.get("is_directory", False)
        original_filename = metadata.get("filename", "decrypted_data")
        expected_sha256 = metadata.get("sha256", "")
        payload_size = metadata.get("orig_size", 0)

        # Determine target output path
        if is_directory:
            temp_decrypted_zip = os.path.join(target_dir, f".temp_{int(time.time())}.zip")
            output_path = temp_decrypted_zip
            final_target_dir = os.path.join(target_dir, original_filename)
        else:
            # Check collision
            output_path = os.path.join(target_dir, original_filename)
            if os.path.abspath(output_path) == os.path.abspath(encrypted_file):
                output_path = os.path.join(target_dir, f"decrypted_{original_filename}")

        # Payload calculation
        header_size = 6 + 1 + cls.SALT_SIZE + cls.NONCE_SIZE + 4 + meta_block_len
        ciphertext_size = total_file_size - header_size - cls.TAG_SIZE

        if ciphertext_size < 0:
            raise ValueError("Corrupted encrypted payload: Incomplete ciphertext.")

        start_time = time.time()
        processed_bytes = 0
        hasher = hashlib.sha256()

        try:
            with open(output_path, "wb") as dst:
                remaining = ciphertext_size
                while remaining > 0:
                    if cancel_event and cancel_event.is_set():
                        raise InterruptedError("Operation canceled by user.")

                    read_amount = min(cls.CHUNK_SIZE, remaining)
                    chunk = src.read(read_amount)
                    if not chunk:
                        raise ValueError("Unexpected EOF while streaming ciphertext.")

                    dec_chunk = cipher.decrypt(chunk)
                    dst.write(dec_chunk)
                    hasher.update(dec_chunk)

                    processed_bytes += len(chunk)
                    remaining -= len(chunk)

                    elapsed = max(0.001, time.time() - start_time)
                    speed_mbps = (processed_bytes / (1024 * 1024)) / elapsed
                    eta_sec = remaining / max(1.0, (processed_bytes / elapsed))

                    if progress_callback:
                        pct = (processed_bytes / max(1, ciphertext_size)) * 100
                        speed_str = f"{speed_mbps:.1f} MB/s"
                        eta_str = f"{int(eta_sec)}s left" if eta_sec < 3600 else "> 1h"
                        progress_callback(pct, speed_str, eta_str)

                # Authenticate tag
                tag = src.read(cls.TAG_SIZE)
                if len(tag) != cls.TAG_SIZE:
                    raise ValueError("Authentication tag missing or truncated.")

                cipher.verify(tag)

            # Verify end-to-end payload checksum
            calculated_hash = hasher.hexdigest()
            if expected_sha256 and calculated_hash != expected_sha256:
                raise ValueError("Integrity check failed: Payload SHA-256 hash mismatch!")

            if is_directory:
                # Extract archive into directory
                FolderProcessor.unpack_archive_safely(output_path, final_target_dir)
                try:
                    os.remove(output_path)
                except OSError:
                    pass
                final_output = final_target_dir
            else:
                final_output = output_path

            if progress_callback:
                progress_callback(100.0, "Decrypted", "0s")

            return {
                "status": "success",
                "output_path": final_output,
                "original_filename": original_filename,
                "is_directory": is_directory,
                "sha256": calculated_hash,
                "bytes_restored": processed_bytes
            }

        except Exception as err:
            # Secure rollback
            if os.path.exists(output_path):
                try:
                    os.remove(output_path)
                except OSError:
                    pass
            raise ValueError(f"Decryption failed: {str(err)}") from err

    @classmethod
    def _decrypt_v1(
        cls,
        src,
        total_file_size: int,
        encrypted_file: str,
        target_dir: str,
        password: str,
        progress_callback: Optional[Callable[[float, str, str], None]],
        cancel_event: Optional[threading.Event]
    ) -> Dict[str, Any]:
        """Legacy V1 decryption handler."""
        salt = src.read(cls.SALT_SIZE)
        nonce = src.read(cls.NONCE_SIZE)

        header_len = 6 + 1 + cls.SALT_SIZE + cls.NONCE_SIZE
        ciphertext_size = total_file_size - header_len - cls.TAG_SIZE

        key = cls.derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        base_name = os.path.basename(encrypted_file)
        if base_name.lower().endswith(".aes"):
            out_name = base_name[:-4] + "_decrypted"
        else:
            out_name = base_name + "_decrypted"
        output_path = os.path.join(target_dir, out_name)

        start_time = time.time()
        processed_bytes = 0

        try:
            with open(output_path, "wb") as dst:
                remaining = ciphertext_size
                while remaining > 0:
                    if cancel_event and cancel_event.is_set():
                        raise InterruptedError("Operation canceled by user.")

                    read_amount = min(cls.CHUNK_SIZE, remaining)
                    chunk = src.read(read_amount)
                    if not chunk:
                        raise ValueError("Unexpected EOF in ciphertext.")

                    dec_chunk = cipher.decrypt(chunk)
                    dst.write(dec_chunk)

                    processed_bytes += len(chunk)
                    remaining -= len(chunk)

                    elapsed = max(0.001, time.time() - start_time)
                    speed_mbps = (processed_bytes / (1024 * 1024)) / elapsed
                    if progress_callback:
                        pct = (processed_bytes / max(1, ciphertext_size)) * 100
                        progress_callback(pct, f"{speed_mbps:.1f} MB/s", "Legacy V1")

                tag = src.read(cls.TAG_SIZE)
                cipher.verify(tag)

            return {
                "status": "success",
                "output_path": output_path,
                "original_filename": out_name,
                "is_directory": False,
                "sha256": cls.calculate_file_hash(output_path),
                "bytes_restored": processed_bytes
            }

        except Exception as err:
            if os.path.exists(output_path):
                try:
                    os.remove(output_path)
                except OSError:
                    pass
            raise ValueError(f"Legacy V1 Decryption failed: {str(err)}") from err

    # ============================================================
    # TEXT ENCRYPTION & DECRYPTION (BASE64 ARMORED)
    # ============================================================

    @classmethod
    def encrypt_text(cls, plaintext: str, password: str) -> str:
        """
        Encrypts a unicode string using AES-256-GCM.
        Returns a Base64-armored string containing Salt + Nonce + Tag + Ciphertext.
        """
        if not plaintext:
            return ""

        salt = get_random_bytes(cls.SALT_SIZE)
        nonce = get_random_bytes(cls.NONCE_SIZE)
        key = cls.derive_key(password, salt)

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))

        package = salt + nonce + tag + ciphertext
        return base64.b64encode(package).decode("utf-8")

    @classmethod
    def decrypt_text(cls, armored_text: str, password: str) -> str:
        """
        Decrypts a Base64-armored AES-256-GCM string.
        """
        if not armored_text:
            return ""

        try:
            package = base64.b64decode(armored_text.strip().encode("utf-8"))
        except Exception:
            raise ValueError("Invalid Base64 ciphertext format.")

        min_len = cls.SALT_SIZE + cls.NONCE_SIZE + cls.TAG_SIZE
        if len(package) < min_len:
            raise ValueError("Malformed ciphertext package (incomplete headers).")

        salt = package[:cls.SALT_SIZE]
        nonce = package[cls.SALT_SIZE:cls.SALT_SIZE + cls.NONCE_SIZE]
        tag = package[cls.SALT_SIZE + cls.NONCE_SIZE:cls.SALT_SIZE + cls.NONCE_SIZE + cls.TAG_SIZE]
        ciphertext = package[min_len:]

        key = cls.derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        try:
            decrypted_bytes = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted_bytes.decode("utf-8")
        except (ValueError, KeyError) as err:
            raise ValueError("Decryption failed: Incorrect password or corrupted text.") from err
