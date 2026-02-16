from __future__ import annotations

import secrets
import string

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


def _pick_letter_pools(excluded: set[str]) -> tuple[list[str], list[str], list[str]]:
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
                break

    return "".join(chars)


def generate_password(length: int, exclude: str = "", pronounceable: bool = False) -> str:
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
