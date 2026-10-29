"""Password storage for Bayyina's local break-glass accounts. Rules: README.md, "What to build", part 3."""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re
import unicodedata

SCHEME = "scrypt"
N = 2 ** 14
R = 8
P = 5
SALT_BYTES = 16
KEY_BYTES = 32
MAXMEM = 64 * 1024 * 1024

MIN_LEN = 8
MAX_LEN = 128
_VERIFY_PASSWORD_CAP = 1024     # verify never hashes absurdly long input

# ASCII digits only: int() also accepts Arabic-Indic digits, spaces, "_" and signs.
_INT_RE = re.compile(r"[0-9]{1,10}")
_B64_RE = re.compile(r"[A-Za-z0-9_-]+")


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes | None:
    """Strict unpadded URL-safe base64: None unless `text` is exactly the canonical encoding."""
    if not _B64_RE.fullmatch(text):
        return None
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        return None
    return raw if _b64e(raw) == text else None


def _parse(stored: object) -> tuple[int, int, int, bytes, bytes] | None:
    """Split a stored string into (n, r, p, salt, key); None if the format is wrong."""
    if not isinstance(stored, str):
        return None
    parts = stored.split("$")
    if len(parts) != 6 or parts[0] != SCHEME:
        return None
    if not all(_INT_RE.fullmatch(x) for x in parts[1:4]):
        return None
    n, r, p = (int(x) for x in parts[1:4])
    salt = _b64d(parts[4])
    key = _b64d(parts[5])
    if salt is None or key is None:
        return None
    return n, r, p, salt, key


def _params_ok(n: int, r: int, p: int, salt: bytes, key: bytes) -> bool:
    """Bounds that must hold BEFORE scrypt runs (a huge p would burn minutes of CPU)."""
    return (
        2 <= n <= 2 ** 20 and (n & (n - 1)) == 0
        and 1 <= r <= 32
        and 1 <= p <= 16
        and len(salt) >= SALT_BYTES
        and len(key) == KEY_BYTES      # the stored value must not choose how many bytes we compare
    )


def hash_password(password: str) -> str:
    """scrypt$<n>$<r>$<p>$<salt>$<hash> with n=2**14, r=8, p=5, a 16-byte random salt, dklen=32."""
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    normalised = unicodedata.normalize("NFKC", password)
    if not MIN_LEN <= len(normalised) <= MAX_LEN:
        raise ValueError(f"password must be {MIN_LEN} to {MAX_LEN} characters")
    try:
        raw = normalised.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("password is not valid text") from None
    salt = os.urandom(SALT_BYTES)
    key = hashlib.scrypt(raw, salt=salt, n=N, r=R, p=P, dklen=KEY_BYTES, maxmem=MAXMEM)
    return f"{SCHEME}${N}${R}${P}${_b64e(salt)}${_b64e(key)}"


def verify_password(password: str, stored: str) -> bool:
    """True only if `password` matches `stored`. Never raises: anything malformed is False."""
    try:
        if not isinstance(password, str):
            return False
        parsed = _parse(stored)
        if parsed is None:
            return False
        n, r, p, salt, key = parsed
        if not _params_ok(n, r, p, salt, key):
            return False
        normalised = unicodedata.normalize("NFKC", password)
        if len(normalised) > _VERIFY_PASSWORD_CAP:
            return False
        candidate = hashlib.scrypt(
            normalised.encode("utf-8"), salt=salt, n=n, r=r, p=p,
            dklen=KEY_BYTES, maxmem=MAXMEM,
        )
        return hmac.compare_digest(candidate, key)
    except (ValueError, TypeError, OverflowError, MemoryError, UnicodeError):
        # scrypt refused the parameters, or the password was not encodable
        return False


def needs_rehash(stored: str) -> bool:
    """True if `stored` cannot be parsed or any of n, r, p is below the current values."""
    parsed = _parse(stored)
    if parsed is None:
        return True
    n, r, p, _salt, _key = parsed
    return n < N or r < R or p < P
