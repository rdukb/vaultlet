from __future__ import annotations

import unittest

from app.passwords import generate_password


class PasswordTests(unittest.TestCase):
    def test_first_char_is_alphabetic(self) -> None:
        pwd = generate_password(24)
        self.assertTrue(pwd[0].isalpha())

    def test_exclusions_enforced(self) -> None:
        pwd = generate_password(16, exclude="abc123!@#")
        for ch in "abc123!@#":
            self.assertNotIn(ch, pwd)

    def test_pronounceable_generation(self) -> None:
        pwd = generate_password(18, pronounceable=True)
        self.assertEqual(len(pwd), 18)
        self.assertTrue(pwd[0].isalpha())


if __name__ == "__main__":
    unittest.main()
