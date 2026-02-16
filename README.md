# Vaultlet
A local-first secrets vault with passkey unlock, encrypted backup import/export, and secure password generation.

## Features
- Local desktop UI on macOS and Windows (Tkinter)
- Secret types: `password`, `api_key`, `secure_note`
- AES-256-GCM encrypted vault at rest
- Device passkey unlock via WebAuthn ceremony in your system browser
- Recovery-key fallback for passkey loss
- Multiple passkeys: enroll, rename, revoke
- Generator tab with explicit "Save to Vault"
- Import support: LastPass CSV and Google Password Manager CSV
- Encrypted Vaultlet backup export/import (UI + CLI, same-vault restore in v1)
- Legacy migration from `pw_history` to vault items (one-time)
- Clipboard auto-clear after copy

## Security model (v1)
- A random vault DEK encrypts each vault item payload.
- DEK is wrapped by:
  - local keychain KEK (`keyring`)
  - recovery-key-derived KEK (`argon2id`)
- Unlock requires a successful WebAuthn passkey assertion for normal flow.
- Auto-lock after 5 minutes of inactivity.

## Requirements
- Python 3.10+
- Dependencies in `requirements.txt`
- Tk runtime
- Browser with WebAuthn support

## Install
```bash
git clone https://github.com/rdukb/vaultlet.git
cd vaultlet
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run desktop app
```bash
source .venv/bin/activate
python -m app.main
```

First run:
1. Initialize vault
2. Save recovery key securely
3. Enroll first passkey

## CLI
```bash
# Vault status
python -m app.main vault status

# Export encrypted backup (interactive passkey auth)
python -m app.main vault export --out backup.vaultlet.json

# Import encrypted backup
python -m app.main vault import --in backup.vaultlet.json

# Import CSV source
python -m app.main vault import-csv --source lastpass --file lastpass.csv
python -m app.main vault import-csv --source google --file google.csv

# Wipe vault
python -m app.main vault wipe
```

## Build (PyInstaller)
```bash
pip install pyinstaller
pyinstaller --onedir --windowed app/main.py --name Vaultlet
```

## Notes
- Plaintext secret export is removed. Use encrypted backup export.
- Passkeys are device-bound and are not portable in backups.
- v1 backup import validates vault keyset and currently supports same-vault restore.
- CSV imports may contain plaintext secrets: delete source files securely after import.

## License
[MIT](./LICENSE)
