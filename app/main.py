from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from app.config import APP_NAME, DB_PATH
from app.importers import IMPORTERS
from app.importers.base import load_csv_rows
from app.vault.db import VaultDB
from app.vault.service import VaultLockedError, VaultService


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Vaultlet local password generator and passkey-secured vault.")
    parser.add_argument("--legacy-export-history", metavar="CSV_PATH", help=argparse.SUPPRESS)
    parser.add_argument("--legacy-wipe-history", action="store_true", help=argparse.SUPPRESS)

    subparsers = parser.add_subparsers(dest="command")

    vault_parser = subparsers.add_parser("vault", help="Vault operations")
    vault_sub = vault_parser.add_subparsers(dest="vault_command", required=True)

    vault_sub.add_parser("status", help="Show vault status")
    vault_sub.add_parser("lock", help="Lock current CLI vault session")

    wipe = vault_sub.add_parser("wipe", help="Wipe all vault data")
    wipe.add_argument("--force", action="store_true", help="Skip destructive confirmation prompt")

    export = vault_sub.add_parser("export", help="Export encrypted backup")
    export.add_argument("--out", required=True, metavar="PATH", help="Output backup path")

    imp = vault_sub.add_parser("import", help="Import encrypted backup")
    imp.add_argument("--in", dest="in_path", required=True, metavar="PATH", help="Input backup path")
    imp.add_argument("--allow-existing", action="store_true", help="Allow import into non-empty vault")

    csv_import = vault_sub.add_parser("import-csv", help="Import LastPass or Google CSV")
    csv_import.add_argument("--source", required=True, choices=["lastpass", "google"])
    csv_import.add_argument("--file", required=True, metavar="CSV_PATH")

    return parser


def _build_services() -> tuple[VaultService, object]:
    db = VaultDB(DB_PATH)
    vault = VaultService(db)
    vault.initialize()

    from app.auth.passkey import PasskeyAuthManager

    passkeys = PasskeyAuthManager(db)
    return vault, passkeys


def _require_cli_unlock(vault: VaultService, passkeys) -> None:
    if vault.is_unlocked_without_touch():
        return

    if not vault.is_setup():
        raise RuntimeError("Vault is not initialized yet. Launch the desktop app to initialize and enroll passkeys.")

    if not sys.stdin.isatty():
        raise RuntimeError("Interactive authentication required. Re-run in an interactive terminal.")

    if passkeys.has_any_passkey():
        result = passkeys.authenticate_passkey()
        if not result.ok:
            raise RuntimeError(result.error or "Passkey authentication failed.")
        vault.unlock_with_local_kek()
        return

    recovery = getpass.getpass("No passkeys found. Enter recovery key: ")
    vault.unlock_with_recovery_key(recovery)


def _print_status(vault: VaultService, passkeys) -> None:
    has_vault = vault.is_setup()
    is_unlocked = vault.is_unlocked_without_touch()
    item_count = len(vault.db.list_items_encrypted(include_deleted=False))
    passkey_count = len(passkeys.list_passkeys())
    print(f"app={APP_NAME}")
    print(f"db={DB_PATH}")
    print(f"vault_initialized={has_vault}")
    print(f"unlocked={is_unlocked}")
    print(f"items={item_count}")
    print(f"active_passkeys={passkey_count}")


def _handle_vault_command(args: argparse.Namespace) -> int:
    vault, passkeys = _build_services()

    if args.vault_command == "status":
        _print_status(vault, passkeys)
        return 0

    if args.vault_command == "lock":
        vault.lock()
        print("Vault locked for this CLI session.")
        return 0

    if args.vault_command == "wipe":
        if not args.force:
            if not sys.stdin.isatty():
                raise RuntimeError("Refusing wipe without --force in non-interactive mode.")
            prompt = input("Type WIPE to permanently delete all vault data: ")
            if prompt.strip() != "WIPE":
                print("Cancelled.")
                return 1

        _require_cli_unlock(vault, passkeys)
        vault.db.wipe_vault()
        vault.lock()
        print("Vault wiped.")
        return 0

    if args.vault_command == "export":
        _require_cli_unlock(vault, passkeys)
        out = vault.export_backup(Path(args.out))
        print(f"Encrypted backup exported: {out}")
        return 0

    if args.vault_command == "import":
        _require_cli_unlock(vault, passkeys)
        count = vault.import_backup(Path(args.in_path), require_empty=not args.allow_existing)
        print(f"Imported encrypted backup items: {count}")
        print("Reminder: passkeys are device-bound and not imported from backup.")
        return 0

    if args.vault_command == "import-csv":
        _require_cli_unlock(vault, passkeys)
        headers, rows = load_csv_rows(Path(args.file))
        if args.source == "lastpass":
            importer = next((imp for imp in IMPORTERS if imp.source_name == "LastPass"), None)
        else:
            importer = next((imp for imp in IMPORTERS if imp.source_name == "Google Password Manager"), None)

        if importer is None:
            raise RuntimeError("Requested importer is unavailable.")

        if not importer.detect(headers):
            print("Warning: CSV headers do not match expected source format. Proceeding anyway.")

        records = importer.parse_rows(rows)
        report = vault.import_records(importer.source_name, records)
        print(
            f"source={importer.source_name} total={report.total_rows} imported={report.imported} "
            f"duplicates={report.duplicates} failed={report.failed}"
        )
        if report.messages:
            print("errors=" + " | ".join(report.messages[:5]))
        print("Security reminder: plaintext CSV exports should be securely deleted after import.")
        return 0

    raise RuntimeError(f"Unsupported vault command: {args.vault_command}")


def _configure_desktop_process_identity() -> None:
    if sys.platform != "darwin":
        return

    try:
        import ctypes
        import ctypes.util

        libc_path = ctypes.util.find_library("c")
        if not libc_path:
            return
        libc = ctypes.CDLL(libc_path)
        if hasattr(libc, "setprogname"):
            libc.setprogname(APP_NAME.encode("utf-8"))
    except Exception:
        pass


def _launch_desktop_app() -> int:
    vault, passkeys = _build_services()
    _configure_desktop_process_identity()
    from app.ui.app import run_desktop_app

    run_desktop_app(vault, passkeys)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.legacy_export_history:
        raise RuntimeError("Legacy plaintext history export has been removed. Use 'vaultlet vault export --out <path>'.")
    if args.legacy_wipe_history:
        raise RuntimeError("Legacy history wipe flag has been replaced by 'vaultlet vault wipe'.")

    if args.command == "vault":
        return _handle_vault_command(args)

    return _launch_desktop_app()


if __name__ == "__main__":
    raise SystemExit(main())
