from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Any

from app.auth.passkey import PasskeyAuthManager
from app.config import APP_NAME, AUTO_LOCK_SECONDS, CLIPBOARD_CLEAR_SEC
from app.importers import IMPORTERS
from app.importers.base import load_csv_rows
from app.migrate.history_to_vault import maybe_migrate_legacy_history
from app.passwords import generate_password
from app.vault.models import VaultItem, VaultItemType
from app.vault.service import VaultLockedError, VaultService


class ItemEditorDialog(tk.Toplevel):
    def __init__(
        self,
        parent: tk.Misc,
        initial_type: VaultItemType,
        initial_payload: dict[str, Any] | None = None,
        allow_type_change: bool = False,
    ):
        super().__init__(parent)
        self.title("Secret item")
        self.transient(parent)
        self.grab_set()
        self.resizable(False, False)

        self.result: tuple[VaultItemType, dict[str, str]] | None = None
        payload = initial_payload or {}

        self.item_type_var = tk.StringVar(value=initial_type.value)
        self.title_var = tk.StringVar(value=str(payload.get("title", "")))
        self.username_var = tk.StringVar(value=str(payload.get("username", "")))
        self.password_var = tk.StringVar(value=str(payload.get("password", "")))
        self.url_var = tk.StringVar(value=str(payload.get("url", "")))
        self.service_var = tk.StringVar(value=str(payload.get("service", "")))
        self.api_key_var = tk.StringVar(value=str(payload.get("api_key", "")))

        frm = ttk.Frame(self, padding=12)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text="Type").grid(row=0, column=0, sticky="e")
        self.type_combo = ttk.Combobox(
            frm,
            textvariable=self.item_type_var,
            values=[t.value for t in VaultItemType],
            state="readonly" if allow_type_change else "disabled",
            width=18,
        )
        self.type_combo.grid(row=0, column=1, sticky="w")
        self.type_combo.bind("<<ComboboxSelected>>", lambda _evt: self._toggle_fields())

        ttk.Label(frm, text="Title").grid(row=1, column=0, sticky="e", pady=(8, 0))
        ttk.Entry(frm, textvariable=self.title_var, width=42).grid(row=1, column=1, sticky="w", pady=(8, 0))

        self.password_frame = ttk.LabelFrame(frm, text="Password", padding=10)
        ttk.Label(self.password_frame, text="Username").grid(row=0, column=0, sticky="e")
        ttk.Entry(self.password_frame, textvariable=self.username_var, width=34).grid(row=0, column=1, sticky="w")
        ttk.Label(self.password_frame, text="Password").grid(row=1, column=0, sticky="e", pady=(6, 0))
        ttk.Entry(self.password_frame, textvariable=self.password_var, width=34).grid(row=1, column=1, sticky="w", pady=(6, 0))
        ttk.Label(self.password_frame, text="URL").grid(row=2, column=0, sticky="e", pady=(6, 0))
        ttk.Entry(self.password_frame, textvariable=self.url_var, width=34).grid(row=2, column=1, sticky="w", pady=(6, 0))

        self.api_frame = ttk.LabelFrame(frm, text="API Key", padding=10)
        ttk.Label(self.api_frame, text="Service").grid(row=0, column=0, sticky="e")
        ttk.Entry(self.api_frame, textvariable=self.service_var, width=34).grid(row=0, column=1, sticky="w")
        ttk.Label(self.api_frame, text="API Key").grid(row=1, column=0, sticky="e", pady=(6, 0))
        ttk.Entry(self.api_frame, textvariable=self.api_key_var, width=34).grid(row=1, column=1, sticky="w", pady=(6, 0))

        self.note_frame = ttk.LabelFrame(frm, text="Secure Note", padding=10)
        ttk.Label(self.note_frame, text="Content").grid(row=0, column=0, sticky="ne")
        self.content_text = tk.Text(self.note_frame, width=34, height=6, wrap="word")
        self.content_text.grid(row=0, column=1, sticky="w")
        self.content_text.insert("1.0", str(payload.get("content", "")))

        ttk.Label(frm, text="Notes").grid(row=5, column=0, sticky="ne", pady=(8, 0))
        self.notes_text = tk.Text(frm, width=42, height=5, wrap="word")
        self.notes_text.grid(row=5, column=1, sticky="w", pady=(8, 0))
        self.notes_text.insert("1.0", str(payload.get("notes", "")))

        buttons = ttk.Frame(frm)
        buttons.grid(row=6, column=0, columnspan=2, pady=(10, 0), sticky="e")
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(side="right")
        ttk.Button(buttons, text="Save", command=self._save).pack(side="right", padx=(0, 8))

        self.password_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        self.api_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        self.note_frame.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        self._toggle_fields()

        self.wait_visibility()
        self.focus_force()

    def _toggle_fields(self) -> None:
        item_type = VaultItemType(self.item_type_var.get())
        if item_type == VaultItemType.PASSWORD:
            self.password_frame.grid()
            self.api_frame.grid_remove()
            self.note_frame.grid_remove()
        elif item_type == VaultItemType.API_KEY:
            self.password_frame.grid_remove()
            self.api_frame.grid()
            self.note_frame.grid_remove()
        else:
            self.password_frame.grid_remove()
            self.api_frame.grid_remove()
            self.note_frame.grid()

    def _save(self) -> None:
        item_type = VaultItemType(self.item_type_var.get())
        payload: dict[str, str] = {
            "title": self.title_var.get().strip() or "Untitled",
            "notes": self.notes_text.get("1.0", "end").strip(),
        }
        if item_type == VaultItemType.PASSWORD:
            payload.update(
                {
                    "username": self.username_var.get().strip(),
                    "password": self.password_var.get(),
                    "url": self.url_var.get().strip(),
                }
            )
        elif item_type == VaultItemType.API_KEY:
            payload.update(
                {
                    "service": self.service_var.get().strip(),
                    "api_key": self.api_key_var.get(),
                }
            )
        else:
            payload.update({"content": self.content_text.get("1.0", "end").strip()})

        self.result = (item_type, payload)
        self.destroy()


class VaultletApp(tk.Tk):
    def __init__(self, vault: VaultService, passkeys: PasskeyAuthManager):
        super().__init__()
        self.vault = vault
        self.passkeys = passkeys

        self.title(APP_NAME)
        self.geometry("980x660")
        self.minsize(920, 620)

        self.generated_password = tk.StringVar(value="")
        self.size_var = tk.IntVar(value=24)
        self.exclude_var = tk.StringVar(value="")
        self.pronounceable_var = tk.BooleanVar(value=False)
        self.search_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="Vault locked")

        self.item_by_id: dict[str, VaultItem] = {}
        self._tabs_enabled = False

        self._build_layout()
        self.after(200, self._startup_flow)
        self.after(1000, self._tick_autolock)

    def _build_layout(self) -> None:
        root = ttk.Frame(self, padding=12)
        root.pack(fill="both", expand=True)

        status_bar = ttk.Frame(root)
        status_bar.pack(fill="x")
        ttk.Label(status_bar, textvariable=self.status_var).pack(side="left")
        ttk.Button(status_bar, text="Unlock (Passkey)", command=self.unlock_with_passkey).pack(side="right")
        ttk.Button(status_bar, text="Unlock (Recovery)", command=self.unlock_with_recovery).pack(side="right", padx=(0, 8))
        ttk.Button(status_bar, text="Lock", command=self.lock_vault).pack(side="right", padx=(0, 8))

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, pady=(10, 0))

        self.generator_tab = ttk.Frame(self.notebook, padding=12)
        self.vault_tab = ttk.Frame(self.notebook, padding=12)
        self.transfer_tab = ttk.Frame(self.notebook, padding=12)
        self.settings_tab = ttk.Frame(self.notebook, padding=12)

        self.notebook.add(self.generator_tab, text="Generator")
        self.notebook.add(self.vault_tab, text="Vault")
        self.notebook.add(self.transfer_tab, text="Import / Export")
        self.notebook.add(self.settings_tab, text="Passkeys")

        self._build_generator_tab()
        self._build_vault_tab()
        self._build_transfer_tab()
        self._build_settings_tab()
        self._set_tabs_enabled(False)

    def _build_generator_tab(self) -> None:
        frm = self.generator_tab

        ttk.Label(frm, text="Password length").grid(row=0, column=0, sticky="e")
        ttk.Spinbox(frm, from_=8, to=128, textvariable=self.size_var, width=8).grid(row=0, column=1, sticky="w")
        ttk.Button(frm, text="Generate", command=self.on_generate).grid(row=0, column=2, sticky="w", padx=(8, 0))

        ttk.Label(frm, text="Exclude chars").grid(row=1, column=0, sticky="e", pady=(8, 0))
        ttk.Entry(frm, textvariable=self.exclude_var, width=24).grid(row=1, column=1, sticky="w", pady=(8, 0))

        ttk.Checkbutton(
            frm,
            text="Pronounceable mode",
            variable=self.pronounceable_var,
        ).grid(row=2, column=0, columnspan=3, sticky="w", pady=(8, 0))

        ttk.Label(frm, text="Generated password").grid(row=3, column=0, sticky="ne", pady=(10, 0))
        self.pwd_entry = ttk.Entry(frm, textvariable=self.generated_password, width=64, show="•")
        self.pwd_entry.grid(row=3, column=1, columnspan=2, sticky="w", pady=(10, 0))

        actions = ttk.Frame(frm)
        actions.grid(row=4, column=1, columnspan=2, sticky="w", pady=(10, 0))
        ttk.Button(actions, text="Reveal / Hide", command=self.toggle_reveal).pack(side="left")
        ttk.Button(actions, text="Copy", command=self.copy_generated).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="Save to Vault", command=self.save_generated_to_vault).pack(side="left", padx=(8, 0))

        ttk.Label(
            frm,
            text="Generated passwords are not auto-stored. Use 'Save to Vault' for explicit storage.",
            foreground="#666",
        ).grid(row=5, column=0, columnspan=3, sticky="w", pady=(12, 0))

    def _build_vault_tab(self) -> None:
        frm = self.vault_tab

        top = ttk.Frame(frm)
        top.pack(fill="x")
        ttk.Label(top, text="Search").pack(side="left")
        search_entry = ttk.Entry(top, textvariable=self.search_var, width=30)
        search_entry.pack(side="left", padx=(6, 10))
        search_entry.bind("<KeyRelease>", lambda _evt: self.refresh_items())

        ttk.Button(top, text="New", command=self.new_item).pack(side="left")
        ttk.Button(top, text="Edit", command=self.edit_selected_item).pack(side="left", padx=(8, 0))
        ttk.Button(top, text="Delete", command=self.delete_selected_item).pack(side="left", padx=(8, 0))
        ttk.Button(top, text="Copy Secret", command=self.copy_selected_secret).pack(side="left", padx=(8, 0))

        main = ttk.PanedWindow(frm, orient="horizontal")
        main.pack(fill="both", expand=True, pady=(10, 0))

        left = ttk.Frame(main)
        right = ttk.Frame(main)
        main.add(left, weight=3)
        main.add(right, weight=2)

        columns = ("type", "title", "updated")
        self.item_tree = ttk.Treeview(left, columns=columns, show="headings", height=20)
        self.item_tree.heading("type", text="Type")
        self.item_tree.heading("title", text="Title")
        self.item_tree.heading("updated", text="Updated")
        self.item_tree.column("type", width=120, anchor="w")
        self.item_tree.column("title", width=340, anchor="w")
        self.item_tree.column("updated", width=180, anchor="w")
        self.item_tree.pack(fill="both", expand=True)
        self.item_tree.bind("<<TreeviewSelect>>", lambda _evt: self._show_selected_item_details())

        ttk.Label(right, text="Secret details").pack(anchor="w")
        self.details = tk.Text(right, wrap="word", height=24)
        self.details.pack(fill="both", expand=True, pady=(8, 0))

    def _build_transfer_tab(self) -> None:
        frm = self.transfer_tab
        btns = ttk.Frame(frm)
        btns.pack(fill="x")

        ttk.Button(btns, text="Import LastPass CSV", command=lambda: self.import_from_csv("lastpass")).pack(side="left")
        ttk.Button(btns, text="Import Google CSV", command=lambda: self.import_from_csv("google")).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(btns, text="Import Vaultlet Backup", command=self.import_backup).pack(side="left", padx=(8, 0))
        ttk.Button(btns, text="Export Encrypted Backup", command=self.export_backup).pack(side="left", padx=(8, 0))

        self.transfer_report = tk.Text(frm, wrap="word", height=28)
        self.transfer_report.pack(fill="both", expand=True, pady=(10, 0))
        self.transfer_report.insert(
            "1.0",
            "Import wizard behavior:\n"
            "1. Choose source format\n"
            "2. Parse and deduplicate\n"
            "3. Import and show summary\n"
            "4. Show secure cleanup guidance for plaintext CSV files\n",
        )

    def _build_settings_tab(self) -> None:
        frm = self.settings_tab
        top = ttk.Frame(frm)
        top.pack(fill="x")

        ttk.Button(top, text="Enroll passkey", command=self.enroll_passkey).pack(side="left")
        ttk.Button(top, text="Rename", command=self.rename_passkey).pack(side="left", padx=(8, 0))
        ttk.Button(top, text="Revoke", command=self.revoke_passkey).pack(side="left", padx=(8, 0))

        self.passkey_tree = ttk.Treeview(frm, columns=("label", "created", "last_used"), show="headings", height=20)
        self.passkey_tree.heading("label", text="Label")
        self.passkey_tree.heading("created", text="Created")
        self.passkey_tree.heading("last_used", text="Last Used")
        self.passkey_tree.column("label", width=260)
        self.passkey_tree.column("created", width=180)
        self.passkey_tree.column("last_used", width=180)
        self.passkey_tree.pack(fill="both", expand=True, pady=(10, 0))

    def _set_tabs_enabled(self, enabled: bool) -> None:
        for idx in range(self.notebook.index("end")):
            self.notebook.tab(idx, state="normal" if enabled else "disabled")
        self._tabs_enabled = enabled

    def _startup_flow(self) -> None:
        self.vault.initialize()
        if not self.vault.is_setup():
            self.run_first_time_setup()
        self._refresh_passkeys()
        self._refresh_status()

    def run_first_time_setup(self) -> None:
        should_setup = messagebox.askyesno(
            "Initialize Vault",
            "Vaultlet needs to initialize your local vault and enroll a passkey. Continue now?",
        )
        if not should_setup:
            return

        try:
            recovery_key = self.vault.setup_new_vault()
        except Exception as exc:
            messagebox.showerror("Setup failed", str(exc))
            return

        messagebox.showinfo(
            "Recovery Key",
            "Save this recovery key securely. It is required if all passkeys are lost:\n\n"
            f"{recovery_key}",
        )

        result = self.passkeys.register_passkey("Primary passkey")
        if not result.ok:
            messagebox.showerror("Passkey enrollment failed", result.error or "Unknown error")
            return

        self.vault.unlock_with_local_kek()
        self._post_unlock("Vault initialized and unlocked.")

    def _post_unlock(self, headline: str | None = None) -> None:
        migrated, migration_error = maybe_migrate_legacy_history(self.vault)
        if migration_error:
            messagebox.showwarning("Legacy migration", migration_error)
        elif migrated:
            messagebox.showinfo("Legacy migration", f"Migrated {migrated} legacy password history entries.")

        self._set_tabs_enabled(True)
        self.refresh_items()
        self._refresh_passkeys()
        self._refresh_status(headline)

    def _refresh_status(self, extra: str | None = None) -> None:
        if self.vault.is_unlocked_without_touch():
            status = f"Vault unlocked (auto-lock: {AUTO_LOCK_SECONDS // 60} min idle)"
        else:
            self._set_tabs_enabled(False)
            status = "Vault locked"
        if extra:
            status = f"{status} | {extra}"
        self.status_var.set(status)

    def unlock_with_passkey(self) -> None:
        if not self.vault.is_setup():
            self.run_first_time_setup()
            return

        if not self.passkeys.has_any_passkey():
            messagebox.showerror("No passkeys", "No passkeys are enrolled. Unlock with recovery key first.")
            return

        result = self.passkeys.authenticate_passkey()
        if not result.ok:
            messagebox.showerror("Unlock failed", result.error or "Passkey authentication failed.")
            return

        try:
            self.vault.unlock_with_local_kek()
            self._post_unlock("Passkey authentication successful.")
        except Exception as exc:
            messagebox.showerror("Unlock failed", str(exc))

    def unlock_with_recovery(self) -> None:
        if not self.vault.is_setup():
            self.run_first_time_setup()
            return

        recovery = simpledialog.askstring("Recovery key", "Enter your recovery key", parent=self)
        if not recovery:
            return

        try:
            self.vault.unlock_with_recovery_key(recovery)
            self._post_unlock("Unlocked with recovery key.")
        except Exception as exc:
            messagebox.showerror("Recovery unlock failed", str(exc))

    def lock_vault(self) -> None:
        self.vault.lock()
        self._set_tabs_enabled(False)
        self._refresh_status("Locked")

    def _tick_autolock(self) -> None:
        self._refresh_status()
        self.after(1000, self._tick_autolock)

    def on_generate(self) -> None:
        length = self.size_var.get()
        if length < 8 or length > 128:
            messagebox.showerror("Invalid length", "Choose a length between 8 and 128.")
            return

        try:
            pwd = generate_password(length, self.exclude_var.get(), self.pronounceable_var.get())
        except ValueError as exc:
            messagebox.showerror("Generation error", str(exc))
            return

        self.generated_password.set(pwd)

    def toggle_reveal(self) -> None:
        if self.pwd_entry.cget("show") == "":
            self.pwd_entry.configure(show="•")
        else:
            self.pwd_entry.configure(show="")

    def copy_generated(self) -> None:
        val = self.generated_password.get()
        if not val:
            messagebox.showinfo("Nothing to copy", "Generate a password first.")
            return
        self.clipboard_clear()
        self.clipboard_append(val)
        self.update()
        if CLIPBOARD_CLEAR_SEC > 0:
            self.after(CLIPBOARD_CLEAR_SEC * 1000, self._clear_clipboard_safe)

    def _clear_clipboard_safe(self) -> None:
        try:
            self.clipboard_clear()
        except Exception:
            pass

    def save_generated_to_vault(self) -> None:
        if not self.vault.is_unlocked_without_touch():
            messagebox.showinfo("Vault locked", "Unlock the vault before saving.")
            return

        pwd = self.generated_password.get()
        if not pwd:
            messagebox.showinfo("No password", "Generate a password first.")
            return

        dialog = ItemEditorDialog(
            self,
            initial_type=VaultItemType.PASSWORD,
            initial_payload={"title": "Generated password", "password": pwd, "username": "", "url": "", "notes": ""},
            allow_type_change=False,
        )
        self.wait_window(dialog)
        if not dialog.result:
            return

        item_type, payload = dialog.result
        try:
            self.vault.add_item(item_type, payload)
            self.refresh_items()
            self._refresh_status("Password saved to vault.")
        except Exception as exc:
            messagebox.showerror("Save failed", str(exc))

    def refresh_items(self) -> None:
        if not self.vault.is_unlocked_without_touch():
            return

        query = self.search_var.get().strip().lower()
        self.item_by_id.clear()
        for child in self.item_tree.get_children():
            self.item_tree.delete(child)

        try:
            for item in self.vault.list_items():
                title = str(item.payload.get("title", ""))
                if query and query not in title.lower():
                    continue
                self.item_by_id[item.id] = item
                self.item_tree.insert("", "end", iid=item.id, values=(item.item_type.value, title, item.updated_at))
        except VaultLockedError:
            self._refresh_status("Vault locked")
        except Exception as exc:
            messagebox.showerror("Vault error", str(exc))

        self._show_selected_item_details()

    def _selected_item(self) -> VaultItem | None:
        selected = self.item_tree.selection()
        if not selected:
            return None
        return self.item_by_id.get(selected[0])

    def _show_selected_item_details(self) -> None:
        self.details.delete("1.0", "end")
        item = self._selected_item()
        if item is None:
            return

        lines = [
            f"ID: {item.id}",
            f"Type: {item.item_type.value}",
            f"Title: {item.payload.get('title', '')}",
            f"Updated: {item.updated_at}",
            "",
        ]
        for key, value in item.payload.items():
            if key in {"created_at", "updated_at", "title"}:
                continue
            lines.append(f"{key}: {value}")
        self.details.insert("1.0", "\n".join(lines))

    def new_item(self) -> None:
        if not self.vault.is_unlocked_without_touch():
            messagebox.showinfo("Vault locked", "Unlock the vault first.")
            return

        dialog = ItemEditorDialog(self, initial_type=VaultItemType.PASSWORD, allow_type_change=True)
        self.wait_window(dialog)
        if not dialog.result:
            return
        item_type, payload = dialog.result

        try:
            self.vault.add_item(item_type, payload)
            self.refresh_items()
        except Exception as exc:
            messagebox.showerror("Create failed", str(exc))

    def edit_selected_item(self) -> None:
        item = self._selected_item()
        if item is None:
            messagebox.showinfo("Select item", "Choose an item first.")
            return

        dialog = ItemEditorDialog(self, initial_type=item.item_type, initial_payload=item.payload, allow_type_change=False)
        self.wait_window(dialog)
        if not dialog.result:
            return

        _, payload = dialog.result
        try:
            self.vault.update_item(item.id, payload)
            self.refresh_items()
        except Exception as exc:
            messagebox.showerror("Update failed", str(exc))

    def delete_selected_item(self) -> None:
        item = self._selected_item()
        if item is None:
            return

        if not messagebox.askyesno("Delete secret", f"Delete '{item.payload.get('title', 'item')}'?"):
            return

        try:
            self.vault.delete_item(item.id)
            self.refresh_items()
        except Exception as exc:
            messagebox.showerror("Delete failed", str(exc))

    def copy_selected_secret(self) -> None:
        item = self._selected_item()
        if item is None:
            return

        if item.item_type == VaultItemType.PASSWORD:
            value = str(item.payload.get("password", ""))
        elif item.item_type == VaultItemType.API_KEY:
            value = str(item.payload.get("api_key", ""))
        else:
            value = str(item.payload.get("content", ""))

        if not value:
            messagebox.showinfo("Nothing to copy", "Selected item has no secret field.")
            return

        self.clipboard_clear()
        self.clipboard_append(value)
        self.update()
        if CLIPBOARD_CLEAR_SEC > 0:
            self.after(CLIPBOARD_CLEAR_SEC * 1000, self._clear_clipboard_safe)

    def _resolve_importer(self, source_key: str):
        if source_key == "lastpass":
            return next((imp for imp in IMPORTERS if imp.source_name == "LastPass"), None)
        if source_key == "google":
            return next((imp for imp in IMPORTERS if imp.source_name == "Google Password Manager"), None)
        return None

    def _append_transfer_report(self, text: str) -> None:
        self.transfer_report.insert("end", text + "\n")
        self.transfer_report.see("end")

    def import_from_csv(self, source_key: str) -> None:
        if not self.vault.is_unlocked_without_touch():
            messagebox.showinfo("Vault locked", "Unlock vault before import.")
            return

        importer = self._resolve_importer(source_key)
        if importer is None:
            messagebox.showerror("Importer missing", "Importer is unavailable.")
            return

        csv_path = filedialog.askopenfilename(title=f"Import {importer.source_name} CSV", filetypes=[("CSV", "*.csv")])
        if not csv_path:
            return

        try:
            headers, rows = load_csv_rows(Path(csv_path))
            if not importer.detect(headers):
                messagebox.showwarning(
                    "Header mismatch",
                    f"Selected file headers do not look like {importer.source_name}. Attempting import anyway.",
                )
            records = importer.parse_rows(rows)
            total, duplicates, to_import = self.vault.preview_import(records)
            should_continue = messagebox.askyesno(
                "Import preview",
                f"Source: {importer.source_name}\n"
                f"Rows parsed: {total}\n"
                f"Potential duplicates: {duplicates}\n"
                f"Rows to import: {to_import}\n\n"
                "Continue import?",
            )
            if not should_continue:
                self._append_transfer_report(f"[{importer.source_name}] import cancelled after preview.")
                return
            report = self.vault.import_records(importer.source_name, records)
            self.refresh_items()

            self._append_transfer_report(
                f"[{importer.source_name}] rows={report.total_rows}, imported={report.imported}, "
                f"duplicates={report.duplicates}, failed={report.failed}"
            )
            if report.messages:
                self._append_transfer_report("Errors: " + " | ".join(report.messages[:5]))
            self._append_transfer_report(
                "Security reminder: source CSV contains plaintext secrets. Securely delete it after verifying import."
            )
        except Exception as exc:
            messagebox.showerror("Import failed", str(exc))

    def export_backup(self) -> None:
        if not self.vault.is_unlocked_without_touch():
            messagebox.showinfo("Vault locked", "Unlock vault before export.")
            return

        out = filedialog.asksaveasfilename(
            title="Export encrypted backup",
            defaultextension=".vaultlet.json",
            filetypes=[("Vaultlet Backup", "*.vaultlet.json"), ("JSON", "*.json")],
        )
        if not out:
            return

        try:
            path = self.vault.export_backup(Path(out))
            self._append_transfer_report(f"Exported encrypted backup: {path}")
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))

    def import_backup(self) -> None:
        if not self.vault.is_unlocked_without_touch():
            messagebox.showinfo("Vault locked", "Unlock vault before import.")
            return

        in_path = filedialog.askopenfilename(
            title="Import Vaultlet backup",
            filetypes=[("Vaultlet Backup", "*.vaultlet.json *.json"), ("All", "*.*")],
        )
        if not in_path:
            return

        try:
            count = self.vault.import_backup(Path(in_path), require_empty=False)
            self.refresh_items()
            self._append_transfer_report(
                f"Imported encrypted backup items: {count}. Passkeys are device-bound and are not imported."
            )
        except Exception as exc:
            messagebox.showerror("Import failed", str(exc))

    def _refresh_passkeys(self) -> None:
        for child in self.passkey_tree.get_children():
            self.passkey_tree.delete(child)

        for row in self.passkeys.list_passkeys():
            self.passkey_tree.insert(
                "",
                "end",
                iid=str(row.id),
                values=(row.label or f"Passkey {row.id}", row.created_at, row.last_used_at or "never"),
            )

    def enroll_passkey(self) -> None:
        if not self.vault.is_unlocked_without_touch():
            messagebox.showinfo("Vault locked", "Unlock vault before enrolling passkeys.")
            return

        label = simpledialog.askstring("Passkey label", "Label for this passkey", parent=self) or "Passkey"
        result = self.passkeys.register_passkey(label)
        if not result.ok:
            messagebox.showerror("Enrollment failed", result.error or "Unknown error")
            return

        self._refresh_passkeys()
        self._refresh_status("Passkey enrolled")

    def rename_passkey(self) -> None:
        selected = self.passkey_tree.selection()
        if not selected:
            messagebox.showinfo("Select passkey", "Choose a passkey row first.")
            return

        row_id = int(selected[0])
        label = simpledialog.askstring("Rename passkey", "New label", parent=self)
        if not label:
            return

        self.passkeys.rename_passkey(row_id, label)
        self._refresh_passkeys()

    def revoke_passkey(self) -> None:
        selected = self.passkey_tree.selection()
        if not selected:
            messagebox.showinfo("Select passkey", "Choose a passkey row first.")
            return

        passkeys = self.passkeys.list_passkeys()
        if len(passkeys) <= 1:
            messagebox.showwarning("Blocked", "At least one active passkey must remain.")
            return

        row_id = int(selected[0])
        if not messagebox.askyesno("Revoke passkey", "Revoke selected passkey?"):
            return

        self.passkeys.revoke_passkey(row_id)
        self._refresh_passkeys()


def run_desktop_app(vault: VaultService, passkeys: PasskeyAuthManager) -> None:
    app = VaultletApp(vault=vault, passkeys=passkeys)
    app.mainloop()
