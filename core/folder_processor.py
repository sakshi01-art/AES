"""
Directory Packaging and Safe Archive Extraction Subsystem.
Includes automated Zip-Slip directory traversal vulnerability defense.
"""
import os
import zipfile
from typing import Callable, Optional


class FolderProcessor:
    """
    Manages folder-to-archive compression and secure folder extraction.
    Protects against path traversal attacks (Zip Slip).
    """

    @staticmethod
    def pack_directory(
        source_dir: str,
        archive_path: str,
        progress_callback: Optional[Callable[[float, str], None]] = None
    ) -> int:
        """
        Compresses a directory recursively into a zip archive.
        Returns total bytes packed.
        """
        source_dir = os.path.abspath(source_dir)
        file_list = []
        for root, _, files in os.walk(source_dir):
            for f in files:
                file_list.append(os.path.join(root, f))

        total_files = len(file_list)
        total_size = sum(os.path.getsize(p) for p in file_list) if file_list else 0

        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
            for idx, full_path in enumerate(file_list):
                rel_path = os.path.relpath(full_path, start=source_dir)
                zf.write(full_path, arcname=rel_path)

                if progress_callback:
                    pct = ((idx + 1) / (total_files or 1)) * 100
                    progress_callback(pct, f"Archiving: {rel_path} ({idx + 1}/{total_files})")

        return total_size

    @staticmethod
    def unpack_archive_safely(
        archive_path: str,
        destination_dir: str,
        progress_callback: Optional[Callable[[float, str], None]] = None
    ) -> None:
        """
        Safely extracts an archive into destination directory.
        Defends against Zip Slip (arbitrary directory traversal) attacks.
        """
        destination_dir = os.path.abspath(destination_dir)
        os.makedirs(destination_dir, exist_ok=True)

        with zipfile.ZipFile(archive_path, "r") as zf:
            members = zf.infolist()
            total_members = len(members)

            for idx, member in enumerate(members):
                # Security Check: Prevent Zip Slip path traversal
                target_path = os.path.abspath(os.path.join(destination_dir, member.filename))
                if not target_path.startswith(destination_dir + os.sep) and target_path != destination_dir:
                    raise SecurityError(
                        f"Zip Slip security alert: Suspicious archive entry '{member.filename}' "
                        f"attempts to write outside destination path!"
                    )

                zf.extract(member, path=destination_dir)

                if progress_callback:
                    pct = ((idx + 1) / (total_members or 1)) * 100
                    progress_callback(pct, f"Extracting: {member.filename} ({idx + 1}/{total_members})")
