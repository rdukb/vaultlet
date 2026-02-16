from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass
from typing import Any

from app.config import VAULT_KEK_SERVICE_NAME

_KEYRING = None
_AESGCM = None
_ARGON2 = None


class CryptoError(RuntimeError):
    pass


@dataclass(slots=True)
class WrappedBlob:
    ciphertext: bytes
    nonce: bytes
    tag: bytes


@dataclass(slots=True)
class RecoveryKDFParams:
    salt: bytes
    time_cost: int = 3
    memory_cost: int = 65536
    parallelism: int = 1
    hash_len: int = 32

    def to_json(self) -> str:
        payload = {
            "salt": base64.b64encode(self.salt).decode("ascii"),
            "time_cost": self.time_cost,
            "memory_cost": self.memory_cost,
            "parallelism": self.parallelism,
            "hash_len": self.hash_len,
        }
        return json.dumps(payload, separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> "RecoveryKDFParams":
        data = json.loads(raw)
        return cls(
            salt=base64.b64decode(data["salt"].encode("ascii")),
            time_cost=int(data["time_cost"]),
            memory_cost=int(data["memory_cost"]),
            parallelism=int(data["parallelism"]),
            hash_len=int(data["hash_len"]),
        )


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


def _load_argon2() -> Any:
    global _ARGON2
    if _ARGON2 is None:
        from argon2 import low_level as _argon2_low_level

        _ARGON2 = _argon2_low_level
    return _ARGON2


def _encrypt_bytes(key: bytes, plaintext: bytes) -> WrappedBlob:
    aes_cls = _load_aesgcm()
    aes = aes_cls(key)
    nonce = secrets.token_bytes(12)
    combined = aes.encrypt(nonce, plaintext, None)
    tag = combined[-16:]
    return WrappedBlob(ciphertext=combined[:-16], nonce=nonce, tag=tag)


def _decrypt_bytes(key: bytes, wrapped: WrappedBlob) -> bytes:
    aes_cls = _load_aesgcm()
    aes = aes_cls(key)
    return aes.decrypt(wrapped.nonce, wrapped.ciphertext + wrapped.tag, None)


def get_or_create_local_kek() -> bytes:
    keyring = _load_keyring()
    encoded = keyring.get_password(VAULT_KEK_SERVICE_NAME, "master")
    if encoded is None:
        raw = secrets.token_bytes(32)
        keyring.set_password(VAULT_KEK_SERVICE_NAME, "master", base64.b64encode(raw).decode("ascii"))
        return raw

    return base64.b64decode(encoded.encode("ascii"))


def create_data_encryption_key() -> bytes:
    return secrets.token_bytes(32)


def wrap_dek(local_kek: bytes, dek: bytes) -> WrappedBlob:
    return _encrypt_bytes(local_kek, dek)


def unwrap_dek(local_kek: bytes, wrapped: WrappedBlob) -> bytes:
    try:
        return _decrypt_bytes(local_kek, wrapped)
    except Exception as exc:  # cryptography raises InvalidTag
        raise CryptoError("Could not unwrap vault key.") from exc


def generate_recovery_key() -> str:
    raw = base64.urlsafe_b64encode(secrets.token_bytes(24)).decode("ascii").rstrip("=")
    grouped = [raw[i : i + 4] for i in range(0, len(raw), 4)]
    return "-".join(grouped)


def normalize_recovery_key(user_input: str) -> str:
    return user_input.strip().replace(" ", "").replace("-", "")


def derive_recovery_kek(recovery_key: str, params: RecoveryKDFParams) -> bytes:
    normalized = normalize_recovery_key(recovery_key)
    if len(normalized) < 16:
        raise CryptoError("Recovery key is invalid.")

    argon2_low = _load_argon2()
    return argon2_low.hash_secret_raw(
        secret=normalized.encode("utf-8"),
        salt=params.salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=params.hash_len,
        type=argon2_low.Type.ID,
    )


def default_recovery_params() -> RecoveryKDFParams:
    return RecoveryKDFParams(salt=secrets.token_bytes(16))


def encrypt_payload(dek: bytes, payload: bytes) -> WrappedBlob:
    return _encrypt_bytes(dek, payload)


def decrypt_payload(dek: bytes, wrapped: WrappedBlob) -> bytes:
    try:
        return _decrypt_bytes(dek, wrapped)
    except Exception as exc:
        raise CryptoError("Could not decrypt secret payload.") from exc
