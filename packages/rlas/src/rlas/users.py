"""End-user authentication at /authorize.

The AS has to know *who* is authorizing, or `sub` in every token is whatever the
caller typed. This is the smallest login that makes `sub` mean something: a
username and password checked against a local file of scrypt hashes.

`sub` is the user's id in `rlapi`'s `users` table, as a string. Step 5's row
gate compares `orders.customer_id` with it, so the directory and the API's
database must agree. Nothing enforces that yet; it is a manual invariant
until Keycloak replaces this file at step 18.

Out of scope, deliberately: rate limiting, lockout, MFA, password reset. Without
rate limiting the login form can be brute-forced at whatever rate scrypt
allows. ARCHITECTURE.md section 7 excludes DoS and rate limiting from the model,
and that exclusion covers this case too.
"""

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Final

#: scrypt cost parameters (RFC 7914). n=2**15, r=8 is ~32 MiB and tens of ms
#: per guess. Encoded into each hash, so raising them later does not orphan
#: existing entries.
_SCRYPT_N: Final = 2**15
_SCRYPT_R: Final = 8
_SCRYPT_P: Final = 1
_SCRYPT_MAXMEM: Final = 64 * 1024 * 1024


@dataclass(frozen=True)
class User:
    username: str
    sub: str
    roles: tuple[str, ...]


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=n, r=r, p=p, maxmem=_SCRYPT_MAXMEM, dklen=32
    )


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = _scrypt(password, salt, _SCRYPT_N, _SCRYPT_R, _SCRYPT_P)
    b64 = base64.b64encode
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${b64(salt).decode()}${b64(digest).decode()}"


def verify_password(password: str, encoded: str) -> bool:
    scheme, n, r, p, salt, digest = encoded.split("$")
    if scheme != "scrypt":
        return False
    actual = _scrypt(password, base64.b64decode(salt), int(n), int(r), int(p))
    return hmac.compare_digest(actual, base64.b64decode(digest))


class UserDirectory:
    def __init__(self, entries: dict[str, tuple[User, str]]) -> None:
        self._entries = entries
        # Verified against when the username is unknown, so a miss costs the same
        # scrypt as a hit. Without it, response time says which usernames exist.
        self._dummy_hash = hash_password(secrets.token_urlsafe(16))

    @classmethod
    def from_records(cls, records: list[dict[str, object]]) -> "UserDirectory":
        entries: dict[str, tuple[User, str]] = {}
        for record in records:
            username, sub, password_hash = (
                str(record["username"]),
                str(record["sub"]),
                str(record["password_hash"]),
            )
            roles = record["roles"]
            if not isinstance(roles, list):
                msg = f"user {username!r}: roles must be a list"
                raise TypeError(msg)
            entries[username] = (User(username, sub, tuple(map(str, roles))), password_hash)
        return cls(entries)

    @classmethod
    def from_file(cls, path: Path) -> "UserDirectory":
        """Load `{"users": [{"username", "sub", "roles", "password_hash"}, ...]}`."""
        document = json.loads(path.read_text(encoding="utf-8"))
        return cls.from_records(document["users"])

    def authenticate(self, username: str, password: str) -> User | None:
        entry = self._entries.get(username)
        if entry is None:
            verify_password(password, self._dummy_hash)
            return None
        user, password_hash = entry
        return user if verify_password(password, password_hash) else None
