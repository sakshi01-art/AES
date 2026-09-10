"""
Modern CustomTkinter GUI for AES-256-GCM Suite.
Features asynchronous worker threads, non-blocking UI, live MB/s throughput,
DoD shredder controls, secret message vault, and password entropy studio.
"""
import os
import sys
import threading
import time
from tkinter import filedialog, messagebox
from typing import Optional

import customtkinter as ctk

from core.crypto_engine import AESCryptoEngine
from core.password_manager import PasswordManager
from core.shredder import FileShredder


class ModernAESApp(ctk.CTk):
    """
    Main Application Window built with CustomTkinter.
    Provides tabbed interface, thread-safe updates, and real-time security auditing.
    """

    def __init__(self):
        super().__init__()

        # Appearance Configuration
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title("AES-256-GCM Enterprise Cryptographic Suite")
        self.geometry("980x720")
        self.minsize(860, 640)

        # Concurrency & State Management
        self.cancel_event = threading.Event()
        self.active_thread: Optional[threading.Thread] = None
        self.selected_path: str = ""
        self.target_mode: str = "file"  # "file" or "folder"

        self._build_header()
        self._build_tabs()
        self._build_status_bar()

        self._log("System initialized. AES-256-GCM Cryptographic Engine ready.", "INFO")

    # ============================================================
    # UI CONSTRUCTION - HEADER
    # ============================================================

    def _build_header(self):
        header_frame = ctk.CTkFrame(self, corner_radius=0, fg_color=("#1E293B", "#0F172A"), height=85)
        header_frame.pack(fill="x", padx=0, pady=0)

        title_label = ctk.CTkLabel(
            header_frame,
            text="🛡️ AES-256-GCM CRYPTOGRAPHIC SUITE",
            font=ctk.CTkFont(family="Segoe UI", size=22, weight="bold"),
            text_color="#38BDF8"
        )
        title_label.pack(anchor="w", padx=25, pady=(14, 2))

        subtitle_label = ctk.CTkLabel(
            header_frame,
            text="NIST SP 800-38D Authenticated Encryption • DoD 5220.22-M Shredder • PBKDF2 250k Iterations",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color="#94A3B8"
        )
        subtitle_label.pack(anchor="w", padx=25, pady=(0, 12))

    # ============================================================
    # UI CONSTRUCTION - TABS
    # ============================================================

    def _build_tabs(self):
        self.tabview = ctk.CTkTabview(self, corner_radius=12)
        self.tabview.pack(fill="both", expand=True, padx=20, pady=(10, 5))

        self.tab_vault = self.tabview.add("📂 File & Folder Vault")
        self.tab_text = self.tabview.add("💬 Secret Message Vault")
        self.tab_keys = self.tabview.add("🔑 Password & Entropy Studio")
        self.tab_audit = self.tabview.add("📜 Security Audit & Logs")

        self._build_tab_vault()
        self._build_tab_text()
        self._build_tab_keys()
        self._build_tab_audit()

    # ============================================================
    # TAB 1: FILE & FOLDER VAULT
    # ============================================================

    def _build_tab_vault(self):
        parent = self.tab_vault

        # Selection mode radio
        mode_frame = ctk.CTkFrame(parent, fg_color="transparent")
        mode_frame.pack(fill="x", pady=(10, 8), padx=10)

        self.mode_var = ctk.StringVar(value="file")
        mode_segmented = ctk.CTkSegmentedButton(
            mode_frame,
            values=["📄 Single File", "📁 Full Directory"],
            command=self._on_mode_change,
            dynamic_resizing=False,
            width=260
        )
        mode_segmented.set("📄 Single File")
        mode_segmented.pack(side="left")

        # Target Selector Card
        path_card = ctk.CTkFrame(parent, fg_color=("#1E293B", "#1E293B"), corner_radius=10)
        path_card.pack(fill="x", pady=6, padx=10)

        self.path_label = ctk.CTkLabel(
            path_card,
            text="No item selected (Select a file or folder to secure)",
            font=ctk.CTkFont(size=12),
            text_color="#CBD5E1",
            anchor="w"
        )
        self.path_label.pack(side="left", fill="x", expand=True, padx=15, pady=12)

        browse_btn = ctk.CTkButton(
            path_card,
            text="Browse...",
            width=100,
            command=self._browse_target,
            fg_color="#0284C7",
            hover_color="#0369A1"
        )
        browse_btn.pack(side="right", padx=12, pady=8)

        # Target Metadata Badge
        self.badge_label = ctk.CTkLabel(
            parent,
            text="Target Details: None",
            font=ctk.CTkFont(size=11),
            text_color="#64748B",
            anchor="w"
        )
        self.badge_label.pack(fill="x", padx=15, pady=(2, 10))

        # Password Entry Section
        pass_card = ctk.CTkFrame(parent, fg_color=("#1E293B", "#1E293B"), corner_radius=10)
        pass_card.pack(fill="x", pady=6, padx=10)

        # Primary Password
        p_row1 = ctk.CTkFrame(pass_card, fg_color="transparent")
        p_row1.pack(fill="x", padx=15, pady=(12, 6))

        ctk.CTkLabel(p_row1, text="Encryption Password:", width=150, anchor="w", font=ctk.CTkFont(weight="bold")).pack(side="left")
        self.vault_pass_entry = ctk.CTkEntry(p_row1, show="*", placeholder_text="Enter secret master key", width=360)
        self.vault_pass_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.vault_pass_entry.bind("<KeyRelease>", self._on_vault_password_type)

        self.show_pass_btn = ctk.CTkButton(
            p_row1,
            text="👁️",
            width=40,
            fg_color="#334155",
            hover_color="#475569",
            command=self._toggle_password_visibility
        )
        self.show_pass_btn.pack(side="right")

        # Confirm Password
        p_row2 = ctk.CTkFrame(pass_card, fg_color="transparent")
        p_row2.pack(fill="x", padx=15, pady=(4, 12))

        ctk.CTkLabel(p_row2, text="Confirm Password:", width=150, anchor="w", font=ctk.CTkFont(weight="bold")).pack(side="left")
        self.vault_confirm_entry = ctk.CTkEntry(p_row2, show="*", placeholder_text="Re-enter password for verification", width=360)
        self.vault_confirm_entry.pack(side="left", fill="x", expand=True, padx=(0, 50))

        # Quick strength bar inside vault tab
        self.mini_strength_bar = ctk.CTkProgressBar(pass_card, height=6)
        self.mini_strength_bar.set(0)
        self.mini_strength_bar.pack(fill="x", padx=15, pady=(0, 10))

        # Advanced Security Options
        opts_frame = ctk.CTkFrame(parent, fg_color="transparent")
        opts_frame.pack(fill="x", padx=15, pady=6)

        self.opt_shred_var = ctk.BooleanVar(value=False)
        self.opt_shred_chk = ctk.CTkCheckBox(
            opts_frame,
            text="⚡ Secure Shred Source (DoD 5220.22-M 3-Pass Overwrite after encryption)",
            variable=self.opt_shred_var,
            font=ctk.CTkFont(size=12),
            text_color="#F87171",
            checkmark_color="white",
            fg_color="#EF4444"
        )
        self.opt_shred_chk.pack(side="left", pady=4)

        # Action Buttons
        btn_frame = ctk.CTkFrame(parent, fg_color="transparent")
        btn_frame.pack(fill="x", padx=10, pady=(12, 10))

        self.encrypt_btn = ctk.CTkButton(
            btn_frame,
            text="🔒 Encrypt to Vault (.aes)",
            command=self._start_encryption,
            font=ctk.CTkFont(weight="bold", size=13),
            fg_color="#2563EB",
            hover_color="#1D4ED8",
            height=38,
            width=180
        )
        self.encrypt_btn.pack(side="left", padx=(5, 8))

        self.decrypt_btn = ctk.CTkButton(
            btn_frame,
            text="🔓 Decrypt Vault",
            command=self._start_decryption,
            font=ctk.CTkFont(weight="bold", size=13),
            fg_color="#10B981",
            hover_color="#059669",
            height=38,
            width=170
        )
        self.decrypt_btn.pack(side="left", padx=8)

        self.cancel_btn = ctk.CTkButton(
            btn_frame,
            text="⛔ Cancel",
            command=self._cancel_operation,
            font=ctk.CTkFont(weight="bold", size=13),
            fg_color="#DC2626",
            hover_color="#B91C1C",
            state="disabled",
            height=38,
            width=110
        )
        self.cancel_btn.pack(side="left", padx=8)

        clear_btn = ctk.CTkButton(
            btn_frame,
            text="🧹 Clear",
            command=self._clear_vault_inputs,
            fg_color="#475569",
            hover_color="#334155",
            height=38,
            width=90
        )
        clear_btn.pack(side="right", padx=5)

        # Metrics & Live Progress Area
        prog_frame = ctk.CTkFrame(parent, fg_color=("#1E293B", "#1E293B"), corner_radius=10)
        prog_frame.pack(fill="x", padx=10, pady=(8, 10))

        m_row = ctk.CTkFrame(prog_frame, fg_color="transparent")
        m_row.pack(fill="x", padx=15, pady=(10, 4))

        self.prog_status_lbl = ctk.CTkLabel(m_row, text="Status: Idle", font=ctk.CTkFont(size=12, weight="bold"), text_color="#38BDF8")
        self.prog_status_lbl.pack(side="left")

        self.prog_metrics_lbl = ctk.CTkLabel(m_row, text="Speed: 0.0 MB/s • ETA: --", font=ctk.CTkFont(size=12), text_color="#94A3B8")
        self.prog_metrics_lbl.pack(side="right")

        self.vault_progress = ctk.CTkProgressBar(prog_frame, height=10)
        self.vault_progress.set(0)
        self.vault_progress.pack(fill="x", padx=15, pady=(4, 12))

    # ============================================================
    # TAB 2: SECRET MESSAGE VAULT
    # ============================================================

    def _build_tab_text(self):
        parent = self.tab_text

        ctk.CTkLabel(parent, text="Plaintext Secret Message / Note:", font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=15, pady=(12, 4))
        self.msg_plain_text = ctk.CTkTextbox(parent, height=120, font=("Consolas", 12))
        self.msg_plain_text.pack(fill="x", padx=15, pady=(0, 10))

        key_row = ctk.CTkFrame(parent, fg_color="transparent")
        key_row.pack(fill="x", padx=15, pady=4)

        ctk.CTkLabel(key_row, text="Cipher Key:", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=(0, 10))
        self.msg_key_entry = ctk.CTkEntry(key_row, show="*", placeholder_text="Key for message encryption/decryption", width=340)
        self.msg_key_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        enc_msg_btn = ctk.CTkButton(
            key_row,
            text="🔒 Encrypt Text",
            command=self._encrypt_text_message,
            fg_color="#2563EB",
            hover_color="#1D4ED8",
            width=130
        )
        enc_msg_btn.pack(side="left", padx=5)

        dec_msg_btn = ctk.CTkButton(
            key_row,
            text="🔓 Decrypt Text",
            command=self._decrypt_text_message,
            fg_color="#10B981",
            hover_color="#059669",
            width=130
        )
        dec_msg_btn.pack(side="left", padx=5)

        ctk.CTkLabel(parent, text="Armored Ciphertext (Base64 AES-GCM):", font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=15, pady=(14, 4))
        self.msg_cipher_text = ctk.CTkTextbox(parent, height=130, font=("Consolas", 11), text_color="#38BDF8")
        self.msg_cipher_text.pack(fill="x", padx=15, pady=(0, 10))

        btn_row = ctk.CTkFrame(parent, fg_color="transparent")
        btn_row.pack(fill="x", padx=15, pady=6)

        copy_btn = ctk.CTkButton(
            btn_row,
            text="📋 Copy Ciphertext to Clipboard",
            command=self._copy_cipher_to_clipboard,
            fg_color="#0284C7",
            hover_color="#0369A1"
        )
        copy_btn.pack(side="left")

        clear_msg_btn = ctk.CTkButton(
            btn_row,
            text="🧹 Clear Fields",
            command=self._clear_text_fields,
            fg_color="#475569",
            hover_color="#334155",
            width=110
        )
        clear_msg_btn.pack(side="right")

    # ============================================================
    # TAB 3: PASSWORD & ENTROPY STUDIO
    # ============================================================

    def _build_tab_keys(self):
        parent = self.tab_keys

        # Analyzer Card
        ana_card = ctk.CTkFrame(parent, fg_color=("#1E293B", "#1E293B"), corner_radius=10)
        ana_card.pack(fill="x", padx=15, pady=(12, 10))

        ctk.CTkLabel(ana_card, text="Password Entropy & Strength Analyzer (NIST SP 800-63B)", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=15, pady=(12, 6))

        in_row = ctk.CTkFrame(ana_card, fg_color="transparent")
        in_row.pack(fill="x", padx=15, pady=6)

        self.studio_pass_entry = ctk.CTkEntry(in_row, placeholder_text="Type password to evaluate bits of entropy...", font=("Consolas", 12))
        self.studio_pass_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.studio_pass_entry.bind("<KeyRelease>", self._on_studio_password_type)

        self.entropy_badge = ctk.CTkLabel(in_row, text="0.0 bits", font=ctk.CTkFont(family="Consolas", size=13, weight="bold"), text_color="#38BDF8")
        self.entropy_badge.pack(side="right", padx=10)

        self.studio_strength_bar = ctk.CTkProgressBar(ana_card, height=10)
        self.studio_strength_bar.set(0)
        self.studio_strength_bar.pack(fill="x", padx=15, pady=(8, 6))

        self.studio_feedback_lbl = ctk.CTkLabel(
            ana_card,
            text="Rating: Empty • Recommendations: Enter characters to assess brute-force resistance",
            font=ctk.CTkFont(size=11),
            text_color="#94A3B8"
        )
        self.studio_feedback_lbl.pack(anchor="w", padx=15, pady=(2, 12))

        # Generator Card
        gen_card = ctk.CTkFrame(parent, fg_color=("#1E293B", "#1E293B"), corner_radius=10)
        gen_card.pack(fill="x", padx=15, pady=10)

        ctk.CTkLabel(gen_card, text="CSPRNG Cryptographic Password Generator", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=15, pady=(12, 8))

        len_row = ctk.CTkFrame(gen_card, fg_color="transparent")
        len_row.pack(fill="x", padx=15, pady=4)

        self.len_lbl = ctk.CTkLabel(len_row, text="Length: 20 characters", width=140, anchor="w")
        self.len_lbl.pack(side="left")

        self.len_slider = ctk.CTkSlider(len_row, from_=10, to=48, number_of_steps=38, command=self._on_slider_move)
        self.len_slider.set(20)
        self.len_slider.pack(side="left", fill="x", expand=True, padx=10)

        # Options checkboxes
        chk_row = ctk.CTkFrame(gen_card, fg_color="transparent")
        chk_row.pack(fill="x", padx=15, pady=8)

        self.chk_upper = ctk.CTkCheckBox(chk_row, text="Uppercase (A-Z)")
        self.chk_upper.select()
        self.chk_upper.pack(side="left", padx=(0, 15))

        self.chk_lower = ctk.CTkCheckBox(chk_row, text="Lowercase (a-z)")
        self.chk_lower.select()
        self.chk_lower.pack(side="left", padx=15)

        self.chk_digits = ctk.CTkCheckBox(chk_row, text="Digits (0-9)")
        self.chk_digits.select()
        self.chk_digits.pack(side="left", padx=15)

        self.chk_symbols = ctk.CTkCheckBox(chk_row, text="Symbols (!@#$)")
        self.chk_symbols.select()
        self.chk_symbols.pack(side="left", padx=15)

        gen_row = ctk.CTkFrame(gen_card, fg_color="transparent")
        gen_row.pack(fill="x", padx=15, pady=(8, 14))

        gen_btn = ctk.CTkButton(
            gen_row,
            text="🎲 Generate Key",
            command=self._generate_studio_password,
            fg_color="#0284C7",
            hover_color="#0369A1",
            width=140
        )
        gen_btn.pack(side="left", padx=(0, 10))

        self.gen_result_entry = ctk.CTkEntry(gen_row, font=("Consolas", 12), text_color="#10B981")
        self.gen_result_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        copy_gen_btn = ctk.CTkButton(
            gen_row,
            text="📋 Copy",
            width=80,
            fg_color="#334155",
            hover_color="#475569",
            command=self._copy_generated_password
        )
        copy_gen_btn.pack(side="left", padx=(0, 8))

        apply_vault_btn = ctk.CTkButton(
            gen_row,
            text="Use in Vault ➔",
            width=120,
            fg_color="#2563EB",
            hover_color="#1D4ED8",
            command=self._apply_generated_to_vault
        )
        apply_vault_btn.pack(side="right")

    # ============================================================
    # TAB 4: AUDIT & LOGS
    # ============================================================

    def _build_tab_audit(self):
        parent = self.tab_audit

        # SHA-256 tool row
        hash_card = ctk.CTkFrame(parent, fg_color=("#1E293B", "#1E293B"), corner_radius=10)
        hash_card.pack(fill="x", padx=15, pady=(12, 8))

        ctk.CTkLabel(hash_card, text="Standalone SHA-256 Checksum Calculator:", font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=15, pady=(10, 4))
        h_row = ctk.CTkFrame(hash_card, fg_color="transparent")
        h_row.pack(fill="x", padx=15, pady=(0, 10))

        self.hash_entry = ctk.CTkEntry(h_row, font=("Consolas", 11), placeholder_text="Select a file to compute cryptographic hash...")
        self.hash_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        calc_btn = ctk.CTkButton(
            h_row,
            text="Browse & Hash",
            command=self._calculate_standalone_hash,
            fg_color="#0284C7",
            hover_color="#0369A1",
            width=130
        )
        calc_btn.pack(side="right")

        # Log View
        ctk.CTkLabel(parent, text="Cryptographic Activity Audit Trail:", font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=15, pady=(8, 4))
        self.log_textbox = ctk.CTkTextbox(parent, height=220, font=("Consolas", 10), text_color="#CBD5E1")
        self.log_textbox.pack(fill="both", expand=True, padx=15, pady=(0, 10))

        log_btn_row = ctk.CTkFrame(parent, fg_color="transparent")
        log_btn_row.pack(fill="x", padx=15, pady=(0, 10))

        export_btn = ctk.CTkButton(
            log_btn_row,
            text="💾 Export Audit Log",
            command=self._export_logs,
            fg_color="#334155",
            hover_color="#475569",
            width=140
        )
        export_btn.pack(side="left")

        clear_log_btn = ctk.CTkButton(
            log_btn_row,
            text="🧹 Clear Logs",
            command=self._clear_logs,
            fg_color="#334155",
            hover_color="#475569",
            width=110
        )
        clear_log_btn.pack(side="right")

    # ============================================================
    # STATUS BAR
    # ============================================================

    def _build_status_bar(self):
        self.status_bar = ctk.CTkFrame(self, corner_radius=0, height=28, fg_color=("#0F172A", "#0F172A"))
        self.status_bar.pack(fill="x", side="bottom")

        self.status_text_lbl = ctk.CTkLabel(
            self.status_bar,
            text="Ready • Secure Sandbox active",
            font=ctk.CTkFont(size=11),
            text_color="#64748B"
        )
        self.status_text_lbl.pack(side="left", padx=15)

    # ============================================================
    # EVENT HANDLERS - VAULT
    # ============================================================

    def _on_mode_change(self, value: str):
        if "Folder" in value or "Directory" in value:
            self.target_mode = "folder"
        else:
            self.target_mode = "file"
        self._clear_vault_inputs()

    def _browse_target(self):
        if self.target_mode == "file":
            selected = filedialog.askopenfilename(
                title="Select File to Encrypt or Decrypt",
                filetypes=[("All Files", "*.*"), ("Encrypted Vaults", "*.aes")]
            )
        else:
            selected = filedialog.askdirectory(title="Select Folder to Encrypt")

        if selected:
            self.selected_path = os.path.abspath(selected)
            base = os.path.basename(self.selected_path) or self.selected_path
            self.path_label.configure(text=f"Selected: {self.selected_path}")

            # Inspect properties
            if os.path.isdir(self.selected_path):
                self.badge_label.configure(text=f"Target: Directory • Name: {base}")
            else:
                size_mb = os.path.getsize(self.selected_path) / (1024 * 1024)
                self.badge_label.configure(text=f"Target: File • Size: {size_mb:.2f} MB • Name: {base}")

            self._log(f"Selected target: {self.selected_path}", "INFO")

    def _toggle_password_visibility(self):
        current = self.vault_pass_entry.cget("show")
        new_show = "" if current == "*" else "*"
        self.vault_pass_entry.configure(show=new_show)
        self.vault_confirm_entry.configure(show=new_show)
        self.show_pass_btn.configure(text="🔒" if new_show == "" else "👁️")

    def _on_vault_password_type(self, event=None):
        pwd = self.vault_pass_entry.get()
        eval_res = PasswordManager.evaluate_strength(pwd)
        pct = eval_res["score"] / 100.0
        self.mini_strength_bar.set(pct)
        self.mini_strength_bar.configure(progress_color=eval_res["color"])

    def _clear_vault_inputs(self):
        self.selected_path = ""
        self.path_label.configure(text="No item selected (Select a file or folder to secure)")
        self.badge_label.configure(text="Target Details: None")
        self.vault_pass_entry.delete(0, "end")
        self.vault_confirm_entry.delete(0, "end")
        self.mini_strength_bar.set(0)
        self.vault_progress.set(0)
        self.prog_status_lbl.configure(text="Status: Idle")
        self.prog_metrics_lbl.configure(text="Speed: 0.0 MB/s • ETA: --")

    # ============================================================
    # BACKGROUND WORKER - ENCRYPTION / DECRYPTION
    # ============================================================

    def _set_ui_busy(self, busy: bool):
        state = "disabled" if busy else "normal"
        self.encrypt_btn.configure(state=state)
        self.decrypt_btn.configure(state=state)
        self.cancel_btn.configure(state="normal" if busy else "disabled")

    def _start_encryption(self):
        if not self.selected_path or not os.path.exists(self.selected_path):
            messagebox.showwarning("Target Missing", "Please select a valid file or folder first.")
            return

        password = self.vault_pass_entry.get()
        confirm = self.vault_confirm_entry.get()

        if not password:
            messagebox.showwarning("Password Required", "Master encryption password cannot be empty.")
            return

        if password != confirm:
            messagebox.showerror("Mismatch", "Encryption passwords do not match. Please verify.")
            return

        out_file = self.selected_path + ".aes"
        if os.path.exists(out_file):
            if not messagebox.askyesno("File Exists", f"Target file already exists:\n{out_file}\n\nOverwrite?"):
                return

        self.cancel_event.clear()
        self._set_ui_busy(True)
        self.prog_status_lbl.configure(text="Status: Encrypting...")
        self.vault_progress.set(0)
        self._log(f"Starting encryption for '{self.selected_path}'...", "INFO")

        should_shred = self.opt_shred_var.get()

        def worker():
            start_ts = time.time()
            try:
                result = AESCryptoEngine.encrypt_file_or_folder(
                    source_path=self.selected_path,
                    output_file=out_file,
                    password=password,
                    progress_callback=self._async_progress_callback,
                    cancel_event=self.cancel_event
                )

                # Secure shredding if requested
                if should_shred and not self.cancel_event.is_set():
                    self.after(0, lambda: self.prog_status_lbl.configure(text="Status: Secure Shredding Source..."))
                    self._log(f"Applying DoD 5220.22-M 3-Pass shredding to original source...", "WARNING")
                    FileShredder.shred_path(self.selected_path)
                    self._log(f"Source shredded and unlinked.", "SUCCESS")

                elapsed = max(0.1, time.time() - start_ts)
                self.after(0, lambda: self._on_operation_success(
                    "Encryption Successful",
                    f"Vault created successfully:\n{out_file}\n\n"
                    f"Time Elapsed: {elapsed:.2f}s\nSHA-256: {result['sha256']}"
                ))
                self._log(f"Encryption completed: {out_file} (SHA256: {result['sha256'][:16]}...)", "SUCCESS")

            except InterruptedError:
                self.after(0, lambda: self._on_operation_cancelled())
                self._log("Encryption cancelled by user.", "WARNING")
            except Exception as err:
                self.after(0, lambda: self._on_operation_error("Encryption Failed", str(err)))
                self._log(f"Encryption error: {str(err)}", "ERROR")
            finally:
                self.after(0, lambda: self._set_ui_busy(False))

        self.active_thread = threading.Thread(target=worker, daemon=True)
        self.active_thread.start()

    def _start_decryption(self):
        if not self.selected_path or not os.path.exists(self.selected_path):
            messagebox.showwarning("Target Missing", "Please select a valid .aes file to decrypt.")
            return

        if not self.selected_path.lower().endswith(".aes"):
            if not messagebox.askyesno("Confirm", "Selected file does not have a .aes extension. Attempt to decrypt anyway?"):
                return

        password = self.vault_pass_entry.get()
        if not password:
            messagebox.showwarning("Password Required", "Please enter the decryption password.")
            return

        # Target output folder
        target_dir = os.path.dirname(self.selected_path)

        self.cancel_event.clear()
        self._set_ui_busy(True)
        self.prog_status_lbl.configure(text="Status: Authenticating & Decrypting...")
        self.vault_progress.set(0)
        self._log(f"Starting decryption for '{self.selected_path}'...", "INFO")

        def worker():
            start_ts = time.time()
            try:
                result = AESCryptoEngine.decrypt_file(
                    encrypted_file=self.selected_path,
                    output_dir=target_dir,
                    password=password,
                    progress_callback=self._async_progress_callback,
                    cancel_event=self.cancel_event
                )

                elapsed = max(0.1, time.time() - start_ts)
                out_path = result["output_path"]
                self.after(0, lambda: self._on_operation_success(
                    "Decryption Successful",
                    f"Payload decrypted and verified:\n{out_path}\n\n"
                    f"Original Name: {result['original_filename']}\n"
                    f"SHA-256 Checksum: {result['sha256']}\n"
                    f"Time: {elapsed:.2f}s"
                ))
                self._log(f"Decryption succeeded: {out_path} (Integrity verified).", "SUCCESS")

            except InterruptedError:
                self.after(0, lambda: self._on_operation_cancelled())
                self._log("Decryption cancelled by user.", "WARNING")
            except Exception as err:
                self.after(0, lambda: self._on_operation_error("Decryption Failed", str(err)))
                self._log(f"Decryption failed: {str(err)}", "ERROR")
            finally:
                self.after(0, lambda: self._set_ui_busy(False))

        self.active_thread = threading.Thread(target=worker, daemon=True)
        self.active_thread.start()

    def _cancel_operation(self):
        if self.active_thread and self.active_thread.is_alive():
            self.cancel_event.set()
            self.prog_status_lbl.configure(text="Status: Cancelling...")
            self._log("User requested operation cancellation...", "WARNING")

    def _async_progress_callback(self, pct: float, speed_str: str, eta_str: str):
        """Thread-safe UI update scheduler."""
        self.after(0, lambda: self._update_vault_progress(pct, speed_str, eta_str))

    def _update_vault_progress(self, pct: float, speed_str: str, eta_str: str):
        self.vault_progress.set(pct / 100.0)
        self.prog_metrics_lbl.configure(text=f"Speed: {speed_str} • ETA: {eta_str}")
        self.prog_status_lbl.configure(text=f"Progress: {pct:.1f}%")

    def _on_operation_success(self, title: str, details: str):
        self.prog_status_lbl.configure(text="Status: Finished Successfully")
        self.vault_progress.set(1.0)
        messagebox.showinfo(title, details)

    def _on_operation_cancelled(self):
        self.prog_status_lbl.configure(text="Status: Cancelled")
        self.vault_progress.set(0)
        messagebox.showwarning("Cancelled", "Operation was cancelled safely. Output cleaned up.")

    def _on_operation_error(self, title: str, error_msg: str):
        self.prog_status_lbl.configure(text="Status: Error Occurred")
        messagebox.showerror(title, error_msg)

    # ============================================================
    # EVENT HANDLERS - SECRET MESSAGE VAULT
    # ============================================================

    def _encrypt_text_message(self):
        text = self.msg_plain_text.get("1.0", "end-1c").strip()
        pwd = self.msg_key_entry.get()

        if not text:
            messagebox.showwarning("Text Missing", "Please enter plaintext message to encrypt.")
            return
        if not pwd:
            messagebox.showwarning("Key Missing", "Please enter a key/password.")
            return

        try:
            cipher_b64 = AESCryptoEngine.encrypt_text(text, pwd)
            self.msg_cipher_text.delete("1.0", "end")
            self.msg_cipher_text.insert("1.0", cipher_b64)
            self._log(f"Encrypted message ({len(text)} chars) to Base64 payload.", "SUCCESS")
        except Exception as err:
            messagebox.showerror("Error", f"Failed to encrypt text: {str(err)}")

    def _decrypt_text_message(self):
        armored = self.msg_cipher_text.get("1.0", "end-1c").strip()
        pwd = self.msg_key_entry.get()

        if not armored:
            messagebox.showwarning("Ciphertext Missing", "Please enter or paste ciphertext to decrypt.")
            return
        if not pwd:
            messagebox.showwarning("Key Missing", "Please enter decryption key.")
            return

        try:
            plain = AESCryptoEngine.decrypt_text(armored, pwd)
            self.msg_plain_text.delete("1.0", "end")
            self.msg_plain_text.insert("1.0", plain)
            self._log("Decrypted message successfully.", "SUCCESS")
            messagebox.showinfo("Decrypted", "Secret message decrypted and restored to plaintext box!")
        except Exception as err:
            messagebox.showerror("Decryption Failed", str(err))

    def _copy_cipher_to_clipboard(self):
        cipher = self.msg_cipher_text.get("1.0", "end-1c").strip()
        if cipher:
            self.clipboard_clear()
            self.clipboard_append(cipher)
            messagebox.showinfo("Copied", "Ciphertext copied to system clipboard!")

    def _clear_text_fields(self):
        self.msg_plain_text.delete("1.0", "end")
        self.msg_cipher_text.delete("1.0", "end")
        self.msg_key_entry.delete(0, "end")

    # ============================================================
    # EVENT HANDLERS - PASSWORD & ENTROPY STUDIO
    # ============================================================

    def _on_studio_password_type(self, event=None):
        pwd = self.studio_pass_entry.get()
        res = PasswordManager.evaluate_strength(pwd)

        self.entropy_badge.configure(text=f"{res['entropy']} bits")
        pct = res["score"] / 100.0
        self.studio_strength_bar.set(pct)
        self.studio_strength_bar.configure(progress_color=res["color"])

        feedback_str = " • ".join(res["feedback"])
        self.studio_feedback_lbl.configure(text=f"Rating: {res['label']} ({res['score']}/100) • {feedback_str}")

    def _on_slider_move(self, val: float):
        int_val = int(val)
        self.len_lbl.configure(text=f"Length: {int_val} characters")

    def _generate_studio_password(self):
        length = int(self.len_slider.get())
        up = bool(self.chk_upper.get())
        low = bool(self.chk_lower.get())
        num = bool(self.chk_digits.get())
        sym = bool(self.chk_symbols.get())

        pwd = PasswordManager.generate_password(length, up, low, num, sym)
        self.gen_result_entry.delete(0, "end")
        self.gen_result_entry.insert(0, pwd)

        # Trigger analysis
        self.studio_pass_entry.delete(0, "end")
        self.studio_pass_entry.insert(0, pwd)
        self._on_studio_password_type()

        self._log(f"Generated CSPRNG password ({length} chars).", "INFO")

    def _copy_generated_password(self):
        pwd = self.gen_result_entry.get()
        if pwd:
            self.clipboard_clear()
            self.clipboard_append(pwd)
            messagebox.showinfo("Copied", "Generated password copied to clipboard!")

    def _apply_generated_to_vault(self):
        pwd = self.gen_result_entry.get()
        if not pwd:
            self._generate_studio_password()
            pwd = self.gen_result_entry.get()

        self.vault_pass_entry.delete(0, "end")
        self.vault_pass_entry.insert(0, pwd)
        self.vault_confirm_entry.delete(0, "end")
        self.vault_confirm_entry.insert(0, pwd)
        self._on_vault_password_type()

        self.tabview.set("📂 File & Folder Vault")
        messagebox.showinfo("Applied", "Master key transferred to Vault tab entries!")

    # ============================================================
    # EVENT HANDLERS - AUDIT & LOGS
    # ============================================================

    def _calculate_standalone_hash(self):
        target = filedialog.askopenfilename(title="Select File for SHA-256 Calculation")
        if target:
            try:
                checksum = AESCryptoEngine.calculate_file_hash(target)
                self.hash_entry.delete(0, "end")
                self.hash_entry.insert(0, checksum)
                self._log(f"Computed SHA-256 for '{os.path.basename(target)}': {checksum}", "INFO")
            except Exception as err:
                messagebox.showerror("Error", f"Failed to compute hash: {str(err)}")

    def _log(self, message: str, level: str = "INFO"):
        ts = time.strftime("%H:%M:%S")
        line = f"[{ts}] [{level:<7}] {message}\n"
        self.log_textbox.insert("end", line)
        self.log_textbox.see("end")

    def _export_logs(self):
        logs = self.log_textbox.get("1.0", "end-1c")
        if not logs.strip():
            messagebox.showinfo("Empty", "Audit log is empty.")
            return

        dest = filedialog.asksaveasfilename(
            title="Export Audit Log",
            defaultextension=".log",
            filetypes=[("Log Files", "*.log"), ("Text Files", "*.txt")]
        )
        if dest:
            with open(dest, "w", encoding="utf-8") as f:
                f.write(logs)
            messagebox.showinfo("Exported", f"Audit logs saved to:\n{dest}")

    def _clear_logs(self):
        self.log_textbox.delete("1.0", "end")
