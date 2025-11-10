from __future__ import annotations

import base64
import secrets
import sqlite3
import string
from datetime import datetime
from pathlib import Path
from typing import Optional

import tkinter as tk
from tkinter import messagebox, ttk

APP_NAME = "Vaultlet"
SERVICE_NAME = f"{APP_NAME}-key"
DB_DIR = Path.home() / f".{APP_NAME.lower()}"
DB_PATH = DB_DIR / "history.db"
CLIPBOARD_CLEAR_SEC = 30  # set 0 to disable auto-clear
DEFAULT_CHARSET = string.ascii_letters + string.digits + string.punctuation
VOWELS = "aeiou"
CONSONANTS = "bcdfghjklmnpqrstvwxyz"
LEET_REPLACEMENTS = {
    "a": ["@", "4"],
    "e": ["3"],
    "i": ["!", "1"],
    "o": ["0"],
    "u": ["^"],
    "s": ["$"],
    "t": ["7"],
    "g": ["9"],
    "l": ["1"],
    "b": ["8"],
    "z": ["2"],
}

_KEYRING = None
_AESGCM = None
_CACHED_KEY: Optional[bytes] = None


def _load_keyring():
    global _KEYRING
    if _KEYRING is None:
        import keyring as _keyring_mod

        _KEYRING = _keyring_mod
    return _KEYRING


def _load_aesgcm():
    global _AESGCM
    if _AESGCM is None:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _aesgcm_cls

        _AESGCM = _aesgcm_cls
    return _AESGCM


def _get_encryption_key() -> bytes:
    global _CACHED_KEY
    if _CACHED_KEY is None:
        _CACHED_KEY = _get_or_create_key()
    return _CACHED_KEY

def _ensure_dirs():
    DB_DIR.mkdir(parents=True, exist_ok=True)

def _get_or_create_key() -> bytes:
    # 32-byte key for AES-256-GCM, stored in OS keychain
    keyring = _load_keyring()
    key = keyring.get_password(SERVICE_NAME, "master")
    if key is None:
        raw = secrets.token_bytes(32)
        keyring.set_password(SERVICE_NAME, "master", base64.b64encode(raw).decode())
        return raw
    return base64.b64decode(key.encode())

def _db_init():
    _ensure_dirs()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS pw_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            ciphertext BLOB NOT NULL,
            nonce BLOB NOT NULL,
            tag BLOB NOT NULL
        );
    """)
    conn.commit()
    conn.close()

def _encrypt(key: bytes, plaintext: bytes):
    # AES-GCM nonce 12 bytes
    aes_cls = _load_aesgcm()
    aes = aes_cls(key)
    nonce = secrets.token_bytes(12)
    ct = aes.encrypt(nonce, plaintext, None)
    # cryptography returns nonce + ciphertext|tag combined at decrypt time; here we split:
    # For clarity, we’ll keep nonce, and split last 16 bytes as tag (AES-GCM tag length 128 bits)
    tag = ct[-16:]
    ciphertext = ct[:-16]
    return ciphertext, nonce, tag

def _decrypt(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes) -> bytes:
    aes_cls = _load_aesgcm()
    aes = aes_cls(key)
    combined = ciphertext + tag
    return aes.decrypt(nonce, combined, None)

def _store_history(pwd_str: str, size_bytes: int):
    key = _get_encryption_key()
    _db_init()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    ct, nonce, tag = _encrypt(key, pwd_str.encode())
    cur.execute(
        "INSERT INTO pw_history (created_at, size_bytes, ciphertext, nonce, tag) VALUES (?, ?, ?, ?, ?)",
        (datetime.utcnow().isoformat(timespec="seconds") + "Z", size_bytes, ct, nonce, tag)
    )
    conn.commit()
    conn.close()

def _iter_history():
    key = _get_encryption_key()
    _db_init()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    for row in cur.execute("SELECT created_at, size_bytes, ciphertext, nonce, tag FROM pw_history ORDER BY id DESC"):
        created_at, size_bytes, ct, nonce, tag = row
        yield created_at, size_bytes, _decrypt(key, ct, nonce, tag).decode()
    conn.close()

def _wipe_history():
    if DB_PATH.exists():
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("DELETE FROM pw_history;")
        conn.commit()
        conn.close()

def _pick_letter_pools(excluded: set[str]):
    letters_allowed = [ch for ch in string.ascii_letters if ch not in excluded]
    vowel_pool = [ch for ch in letters_allowed if ch.lower() in VOWELS]
    consonant_pool = [ch for ch in letters_allowed if ch.lower() in CONSONANTS]
    return letters_allowed, vowel_pool, consonant_pool


def _generate_pronounceable(length: int, excluded: set[str]) -> str:
    letters_allowed, vowels, consonants = _pick_letter_pools(excluded)
    if not letters_allowed:
        raise ValueError("No alphabetic characters available after applying exclusions.")
    if not vowels or not consonants:
        raise ValueError("Pronounceable mode needs at least one vowel and one consonant after exclusions.")

    chars: list[str] = []
    for idx in range(length):
        pool = consonants if idx % 2 == 0 else vowels
        chars.append(secrets.choice(pool))

    substituted = False
    for idx in range(1, len(chars)):
        base = chars[idx]
        replacements = LEET_REPLACEMENTS.get(base.lower(), ())
        candidates = [rep for rep in replacements if rep not in excluded]
        if candidates and secrets.randbelow(2) == 0:
            chars[idx] = secrets.choice(candidates)
            substituted = True

    if not substituted:
        for idx in range(1, len(chars)):
            base = chars[idx]
            replacements = LEET_REPLACEMENTS.get(base.lower(), ())
            candidates = [rep for rep in replacements if rep not in excluded]
            if candidates:
                chars[idx] = candidates[0]
                substituted = True
                break

    return "".join(chars)


def generate_password(length: int, exclude: str = "", pronounceable: bool = False) -> str:
    """Generate a password, optionally pronounceable and always starting with a letter."""
    if length <= 0:
        raise ValueError("Length must be positive.")

    excluded = set(exclude)

    if pronounceable:
        return _generate_pronounceable(length, excluded)

    letters_allowed, _, _ = _pick_letter_pools(excluded)
    if not letters_allowed:
        raise ValueError("No alphabetic characters available after applying exclusions.")

    allowed = [ch for ch in DEFAULT_CHARSET if ch not in excluded]
    if not allowed:
        raise ValueError("No characters left after applying exclusions.")

    chars = [secrets.choice(letters_allowed)]
    if length > 1:
        chars.extend(secrets.choice(allowed) for _ in range(length - 1))
    return "".join(chars)

def parse_args():
    import argparse

    p = argparse.ArgumentParser(description="Local password generator with silent, encrypted history.")
    p.add_argument("--export-history", metavar="CSV_PATH", help="Export full history to CSV (not shown in UI).")
    p.add_argument("--wipe-history", action="store_true", help="Irreversibly wipe stored history.")
    return p.parse_args()

# ------------------------ UI ------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        # Slightly nicer default sizing
        self.geometry("520x260")
        self.resizable(False, False)

        # Vars
        self.size_var = tk.IntVar(value=32)
        self.pwd_var = tk.StringVar(value="")
        self.exclude_var = tk.StringVar(value="")
        self.pronounceable_var = tk.BooleanVar(value=False)

        # Layout
        pad = {"padx": 12, "pady": 8}

        frm = ttk.Frame(self)
        frm.pack(fill="both", expand=True, **pad)

        title = ttk.Label(frm, text="Vaultlet - A simple Password Generator", font=("Segoe UI", 14, "bold"))
        title.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 8))

        ttk.Label(frm, text="Password length:").grid(row=1, column=0, sticky="e")
        size_spin = ttk.Spinbox(frm, from_=8, to=128, textvariable=self.size_var, width=6)
        size_spin.grid(row=1, column=1, sticky="w")

        gen_btn = ttk.Button(frm, text="Generate", command=self.on_generate)
        gen_btn.grid(row=1, column=2, sticky="w", padx=(10, 0))

        ttk.Label(frm, text="Exclude characters:").grid(row=2, column=0, sticky="ne", pady=(10, 0))
        exclude_entry = ttk.Entry(frm, textvariable=self.exclude_var, width=20)
        exclude_entry.grid(row=2, column=1, columnspan=2, sticky="w", pady=(10, 0))

        pronounce_chk = ttk.Checkbutton(
            frm,
            text="Pronounceable (substitute similar symbols)",
            variable=self.pronounceable_var
        )
        pronounce_chk.grid(row=3, column=0, columnspan=3, sticky="w", pady=(6, 0))

        ttk.Label(frm, text="Password:").grid(row=4, column=0, sticky="ne", pady=(10, 0))
        self.out_entry = ttk.Entry(frm, textvariable=self.pwd_var, width=56, show="•")
        self.out_entry.grid(row=4, column=1, columnspan=2, sticky="w", pady=(10, 0))

        reveal_btn = ttk.Button(frm, text="Reveal / Hide", command=self.toggle_reveal)
        reveal_btn.grid(row=5, column=1, sticky="w", pady=(10, 0))

        copy_btn = ttk.Button(frm, text="Copy", command=self.copy_to_clipboard)
        copy_btn.grid(row=5, column=2, sticky="w", pady=(10, 0), padx=(10, 0))

        note = ttk.Label(
            frm,
            text=("History is stored locally, encrypted. Not shown in UI.\n"
                  "Clipboard auto-clears in {}s.").format(CLIPBOARD_CLEAR_SEC if CLIPBOARD_CLEAR_SEC else 0),
            foreground="#666"
        )
        note.grid(row=6, column=0, columnspan=3, sticky="w", pady=(12, 0))

        for i in range(3):
            frm.grid_columnconfigure(i, weight=0)

        # Warm up the database/keyring after initial UI render.
        self.after(200, self._warm_up_history)

    def on_generate(self):
        length = self.size_var.get()
        if length < 8 or length > 128:
            messagebox.showerror("Invalid length", "Choose a length between 8 and 128 characters.")
            return
        try:
            pwd = generate_password(length, self.exclude_var.get(), self.pronounceable_var.get())
        except ValueError as exc:
            messagebox.showerror("Generation error", str(exc))
            return
        self.pwd_var.set(pwd)
        try:
            _store_history(pwd, length)
        except Exception as e:
            messagebox.showwarning("History error", f"Could not save history: {e}")

    def toggle_reveal(self):
        if self.out_entry.cget("show") == "":
            self.out_entry.config(show="•")
        else:
            self.out_entry.config(show="")

    def copy_to_clipboard(self):
        val = self.pwd_var.get()
        if not val:
            messagebox.showinfo("Nothing to copy", "Generate a password first.")
            return
        self.clipboard_clear()
        self.clipboard_append(val)
        self.update()  # ensures clipboard is set
        if CLIPBOARD_CLEAR_SEC > 0:
            self.after(CLIPBOARD_CLEAR_SEC * 1000, self._clear_clipboard_safe)

    def _clear_clipboard_safe(self):
        try:
            self.clipboard_clear()
        except Exception:
            pass

    def _warm_up_history(self):
        try:
            _db_init()
        except Exception:
            pass

def export_history_csv(path: Path):
    _db_init()
    rows = list(_iter_history())
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        f.write("created_at,size_bytes,password\n")
        for created_at, size_bytes, pwd in rows:
            # basic CSV escape
            pwd_escaped = '"' + pwd.replace('"', '""') + '"'
            f.write(f"{created_at},{size_bytes},{pwd_escaped}\n")
    print(f"Exported {len(rows)} entries → {path}")

def main():
    args = parse_args()

    if args.wipe_history:
        _db_init()
        _wipe_history()
        print("History wiped.")
        return

    if args.export_history:
        export_history_csv(Path(args.export_history))
        return

    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()