# Vaultlet 🔐
**A minimalist, cross-platform password generator with encrypted local history.**

Vaultlet creates strong passwords locally, stores them in an encrypted history on disk, and never sends data off device. The first character is always alphabetic, and you can both exclude characters and opt into a pronounceable mode that swaps symbols for familiar sounds.

---

## ✨ Features
- Works on **macOS** and **Windows** with a Tkinter desktop UI
- Passwords pull from ASCII letters, digits, and punctuation with user-defined exclusions
- **Pronounceable** mode alternates consonants/vowels and applies leet-style symbol substitutions
- Clipboard auto-clears after 30 s (configurable in code)
- History is encrypted with AES-GCM; export or wipe from the CLI

---

## � Requirements
- Python **3.10+**
- `cryptography` and `keyring` (installed via `requirements.txt`)
- Tk runtime (macOS Homebrew example: `brew install python-tk@3.12`)
- Optional: `pyinstaller` for packaging a standalone app

---

## 🧱 Installation
```bash
git clone https://github.com/rajeshd/vaultlet.git
cd vaultlet
python -m venv .venv
source .venv/bin/activate   # Windows: .\.venv\Scripts\activate
pip install -r requirements.txt
```

### macOS Tk setup
Homebrew Python builds ship without Tk; install it once per machine:
```bash
brew install python-tk@3.12
```
Re-create your virtual environment after installing to pick up `_tkinter`.

---

## 🚀 Running
```bash
source .venv/bin/activate
python -m app.main
```

UI options let you:
- Choose password length (8–128)
- Exclude characters from the allowed alphabet
- Toggle pronounceable mode that keeps the first character a letter and substitutes symbolic phonetics

---

## 🛠️ Build (PyInstaller)
```bash
pip install pyinstaller
pyinstaller --onefile --windowed app/main.py --name Vaultlet
```
The resulting binary lives under `dist/Vaultlet`. Include the `requirements.txt` dependencies (especially `tk`, `cryptography`, and `keyring`) on the target system.

---

## 🧰 CLI Utilities
```bash
# Export encrypted history to CSV
python -m app.main --export-history history.csv

# Wipe stored history
python -m app.main --wipe-history
```

---

## 🔒 Security
- AES-256-GCM encryption with a per-user key stored in the OS keychain via `keyring`
- Passwords never leave your system
- No telemetry, analytics, or cloud sync

---

## 📜 License
[MIT](./LICENSE) © 2025 Rajesh Dorairajan
