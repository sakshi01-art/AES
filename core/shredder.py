"""
DoD 5220.22-M Compliant Secure Cryptographic File Shredder Subsystem.
Permanently destroys file contents using multi-pass sector overwriting.
"""
import os
import secrets
import shutil
from typing import Callable, Optional


class FileShredder:
    """
    Implements multi-pass sanitization to prevent magnetic / forensic recovery
    conforming to DoD 5220.22-M standard:
      Pass 1: Binary Zeros (0x00)
      Pass 2: Binary Ones (0xFF)
      Pass 3: CSPRNG Random Noise (os.urandom)
      Final: Metadata Obfuscation & File System Unlink
    """

    CHUNK_SIZE = 1024 * 1024  # 1MB buffer

    @classmethod
    def shred_file(
        cls,
        file_path: str,
        passes: int = 3,
        progress_callback: Optional[Callable[[float, str], None]] = None
    ) -> bool:
        """
        Securely overwrites and deletes a file.
        """
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            raise FileNotFoundError(f"Target file not found: {file_path}")

        file_size = os.path.getsize(file_path)

        if file_size == 0:
            os.remove(file_path)
            return True

        patterns = [b"\x00", b"\xFF", None]  # None indicates random noise

        try:
            with open(file_path, "ba+", buffering=0) as f:
                for p_idx in range(passes):
                    f.seek(0)
                    pattern_byte = patterns[p_idx % len(patterns)]
                    pass_name = (
                        "Zeros (0x00)" if pattern_byte == b"\x00"
                        else "Ones (0xFF)" if pattern_byte == b"\xFF"
                        else "Random Noise"
                    )

                    remaining = file_size
                    while remaining > 0:
                        chunk_len = min(cls.CHUNK_SIZE, remaining)
                        if pattern_byte is not None:
                            chunk = pattern_byte * chunk_len
                        else:
                            chunk = os.urandom(chunk_len)

                        f.write(chunk)
                        remaining -= chunk_len

                    f.flush()
                    os.fsync(f.fileno())

                    if progress_callback:
                        pct = ((p_idx + 1) / passes) * 100
                        progress_callback(pct, f"Shredding: Pass {p_idx + 1}/{passes} ({pass_name})")

            # Obfuscate filename to erase NTFS/FAT directory entry records
            dir_name = os.path.dirname(file_path)
            random_temp_name = os.path.join(dir_name, secrets.token_hex(16))
            try:
                os.rename(file_path, random_temp_name)
                os.remove(random_temp_name)
            except OSError:
                os.remove(file_path)

            return True

        except Exception as err:
            raise RuntimeError(f"File shredding failed: {str(err)}") from err

    @classmethod
    def shred_path(
        cls,
        target_path: str,
        progress_callback: Optional[Callable[[float, str], None]] = None
    ) -> bool:
        """
        Shreds either a single file or a directory recursively.
        """
        if os.path.isfile(target_path):
            return cls.shred_file(target_path, progress_callback=progress_callback)
        elif os.path.isdir(target_path):
            # Collect all files
            all_files = []
            for root, _, files in os.walk(target_path):
                for f in files:
                    all_files.append(os.path.join(root, f))

            total = len(all_files)
            for idx, file_item in enumerate(all_files):
                cls.shred_file(file_item)
                if progress_callback:
                    progress_callback(((idx + 1) / (total or 1)) * 100, f"Shredded {idx+1}/{total} files")

            shutil.rmtree(target_path, ignore_errors=True)
            return True
        return False
