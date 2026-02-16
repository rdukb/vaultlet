from __future__ import annotations

import json
import secrets
from dataclasses import dataclass

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import options_to_json
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)

from app.auth.loopback import run_webauthn_loopback
from app.config import APP_NAME, PASSKEY_USER
from app.vault.db import PasskeyCredentialRow, VaultDB
from app.vault.models import utc_now_iso


@dataclass(slots=True)
class PasskeyResult:
    ok: bool
    error: str | None = None


class PasskeyAuthManager:
    def __init__(self, db: VaultDB, rp_id: str = "localhost", rp_name: str = APP_NAME):
        self.db = db
        self.rp_id = rp_id
        self.rp_name = rp_name

    def list_passkeys(self) -> list[PasskeyCredentialRow]:
        return self.db.list_passkeys(include_revoked=False)

    def has_any_passkey(self) -> bool:
        return bool(self.list_passkeys())

    def register_passkey(self, label: str | None = None) -> PasskeyResult:
        challenge = secrets.token_bytes(32)

        exclude = [
            PublicKeyCredentialDescriptor(id=row.credential_id) for row in self.db.list_passkeys(include_revoked=False)
        ]
        registration = generate_registration_options(
            rp_id=self.rp_id,
            rp_name=self.rp_name,
            user_id=PASSKEY_USER.encode("utf-8"),
            user_name=PASSKEY_USER,
            user_display_name=PASSKEY_USER,
            challenge=challenge,
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.REQUIRED
            ),
            exclude_credentials=exclude,
        )

        registration_json = json.loads(options_to_json(registration))

        def get_options() -> dict:
            return registration_json

        def verify_credential(credential: dict, origin: str) -> tuple[bool, str | None, dict | None]:
            try:
                verified = verify_registration_response(
                    credential=credential,
                    expected_challenge=challenge,
                    expected_rp_id=self.rp_id,
                    expected_origin=origin,
                    require_user_verification=True,
                )
                self.db.add_passkey_credential(
                    credential_id=verified.credential_id,
                    public_key_cose=verified.credential_public_key,
                    sign_count=verified.sign_count,
                    label=label,
                    aaguid=str(verified.aaguid),
                    created_at=utc_now_iso(),
                )
                return True, None, {"credential_id": verified.credential_id.hex()}
            except Exception as exc:
                return False, str(exc), None

        result = run_webauthn_loopback("register", get_options, verify_credential)
        return PasskeyResult(ok=result.ok, error=result.error)

    def authenticate_passkey(self) -> PasskeyResult:
        passkeys = self.db.list_passkeys(include_revoked=False)
        if not passkeys:
            return PasskeyResult(ok=False, error="No passkeys are enrolled.")

        challenge = secrets.token_bytes(32)
        allow = [PublicKeyCredentialDescriptor(id=row.credential_id) for row in passkeys]
        auth_options = generate_authentication_options(
            rp_id=self.rp_id,
            challenge=challenge,
            allow_credentials=allow,
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        auth_options_json = json.loads(options_to_json(auth_options))

        def get_options() -> dict:
            return auth_options_json

        def verify_credential(credential: dict, origin: str) -> tuple[bool, str | None, dict | None]:
            try:
                import base64

                candidate = None
                raw_id = credential.get("rawId")
                if isinstance(raw_id, str):
                    pad = "=" * ((4 - len(raw_id) % 4) % 4)
                    raw = base64.urlsafe_b64decode((raw_id + pad).encode("ascii"))
                    candidate = self.db.get_passkey_by_credential_id(raw)

                if candidate is None:
                    return False, "Unknown passkey credential.", None

                verified = verify_authentication_response(
                    credential=credential,
                    expected_challenge=challenge,
                    expected_rp_id=self.rp_id,
                    expected_origin=origin,
                    credential_public_key=candidate.public_key_cose,
                    credential_current_sign_count=candidate.sign_count,
                    require_user_verification=True,
                )
                self.db.update_passkey_sign_count(candidate.credential_id, verified.new_sign_count, utc_now_iso())
                return True, None, {"credential_id": candidate.credential_id.hex()}
            except Exception as exc:
                return False, str(exc), None

        result = run_webauthn_loopback("authenticate", get_options, verify_credential)
        return PasskeyResult(ok=result.ok, error=result.error)

    def revoke_passkey(self, row_id: int) -> None:
        self.db.revoke_passkey(row_id, utc_now_iso())

    def rename_passkey(self, row_id: int, label: str) -> None:
        self.db.rename_passkey(row_id, label)
