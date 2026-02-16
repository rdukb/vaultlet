from __future__ import annotations

import secrets
import unittest

from app.vault.crypto import (
    RecoveryKDFParams,
    create_data_encryption_key,
    decrypt_payload,
    default_recovery_params,
    derive_recovery_kek,
    encrypt_payload,
    wrap_dek,
    unwrap_dek,
)


class CryptoTests(unittest.TestCase):
    def test_encrypt_roundtrip(self) -> None:
        dek = create_data_encryption_key()
        wrapped = encrypt_payload(dek, b"hello-world")
        plain = decrypt_payload(dek, wrapped)
        self.assertEqual(plain, b"hello-world")

    def test_wrap_unwrap_dek_roundtrip(self) -> None:
        kek = secrets.token_bytes(32)
        dek = create_data_encryption_key()
        wrapped = wrap_dek(kek, dek)
        self.assertEqual(unwrap_dek(kek, wrapped), dek)

    def test_recovery_kdf_is_deterministic(self) -> None:
        params = default_recovery_params()
        key1 = derive_recovery_kek("ABCD-EFGH-IJKL-MNOP", params)
        key2 = derive_recovery_kek("ABCDEFGHIJKLM NOP", params)
        self.assertEqual(key1, key2)

    def test_recovery_params_json(self) -> None:
        params = RecoveryKDFParams(salt=secrets.token_bytes(16), time_cost=2, memory_cost=8192, parallelism=1)
        raw = params.to_json()
        parsed = RecoveryKDFParams.from_json(raw)
        self.assertEqual(parsed.salt, params.salt)
        self.assertEqual(parsed.time_cost, params.time_cost)


if __name__ == "__main__":
    unittest.main()
