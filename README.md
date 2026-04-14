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

## Install (uv recommended)
```bash
git clone https://github.com/rdukb/vaultlet.git
cd vaultlet
uv venv
source .venv/bin/activate
uv pip install -r requirements.txt
```

If you do not use `uv`, you can use `python -m venv` and `pip` instead.

## Run desktop app (uv)
```bash
uv run python -m app.main
```

On macOS, this developer-mode launch is expected to show the window title as `Vaultlet` but the menu bar app name may still appear as `Python`. That menu bar label comes from the host interpreter process, not just the Tk window title.

If you want to verify native macOS app identity (`Vaultlet` in the menu bar / Dock), test using a packaged app bundle instead of `uv run`.

## First-run setup (detailed)
1. Launch the app:
   - `uv run python -m app.main`
2. In the setup prompt, click **Yes** to initialize your local vault.
3. Vaultlet will show a **Recovery Key**:
   - Copy it immediately.
   - Store it in a secure place outside Vaultlet (for example: offline password manager entry, printed copy in safe).
   - This is required if all passkeys are lost.
4. Vaultlet opens your system browser for passkey enrollment (`localhost` WebAuthn flow):
   - Click **Continue** in the browser page.
   - Complete biometric/PIN verification on your device.
5. Return to the app. Vault should now be unlocked and ready.
6. Optional hardening right away:
   - Go to the **Passkeys** tab and enroll a second backup passkey on another device.

## CLI
```bash
# Vault status
uv run python -m app.main vault status

# Export encrypted backup (interactive passkey auth)
uv run python -m app.main vault export --out backup.vaultlet.json

# Import encrypted backup
uv run python -m app.main vault import --in backup.vaultlet.json

# Import CSV source
uv run python -m app.main vault import-csv --source lastpass --file lastpass.csv
uv run python -m app.main vault import-csv --source google --file google.csv

# Wipe vault
uv run python -m app.main vault wipe
```

## Build (PyInstaller)
```bash
# run pyinstaller via uv without globally installing it
uvx --from pyinstaller pyinstaller --onedir --windowed app/main.py --name Vaultlet
```

After building on macOS, launch the packaged app bundle to test native app identity:
```bash
open dist/Vaultlet.app
```

If you prefer launching the binary directly:
```bash
./dist/Vaultlet.app/Contents/MacOS/Vaultlet
```

Use the packaged `.app` when checking:
- menu bar app name
- Dock label
- app switching behavior
- other macOS-native window/app identity details

## Migration guide
### A) Migrate from pre-v1 Vaultlet local history (`pw_history`)
- Supported path: automatic one-time migration during first unlocked v1 session.
- What to do:
  1. Start v1 and complete first-run setup.
  2. Unlock vault successfully.
  3. If legacy data exists and the old keychain key is accessible, Vaultlet migrates entries automatically and shows a summary.
- Result:
  - Legacy password history entries are converted into vault `password` items.
  - Legacy table is preserved as backup (`pw_history_legacy_backup`).

### B) Migrate from LastPass
- UI path:
  1. Export CSV from LastPass.
  2. Open Vaultlet -> **Import / Export** tab -> **Import LastPass CSV**.
  3. Review preview (rows, duplicates, to-import), then confirm.
  4. Verify imported items.
- CLI path:
  - `uv run python -m app.main vault import-csv --source lastpass --file lastpass.csv`

### C) Migrate from Google Password Manager
- UI path:
  1. Export CSV from Google Password Manager.
  2. Open Vaultlet -> **Import / Export** tab -> **Import Google CSV**.
  3. Review preview and confirm.
- CLI path:
  - `uv run python -m app.main vault import-csv --source google --file google.csv`

### D) Restore from Vaultlet encrypted backup
- Export:
  - `uv run python -m app.main vault export --out backup.vaultlet.json`
- Import:
  - `uv run python -m app.main vault import --in backup.vaultlet.json`

## Notes
- Plaintext secret export is removed. Use encrypted backup export.
- Passkeys are device-bound and are not portable in backups.
- v1 backup import validates vault keyset and currently supports same-vault restore.
- CSV import behavior:
  - duplicates are skipped and reported
  - unsupported source fields are preserved in item notes metadata
- CSV exports from other tools are plaintext secrets: securely delete source files after successful import.

## License
[MIT](./LICENSE)
