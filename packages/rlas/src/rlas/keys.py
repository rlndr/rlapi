"""The signing key: the crown jewel (ARCHITECTURE.md section 6).

Whoever holds this key can mint any token, for any user, at any audience. Short
token lifetimes limit *replay*; they do nothing against *forgery*. So this module
is mostly about refusing to run with a key that is weak or readable by others.

Three decisions worth knowing:

1. **The key lives in a file, never in the repo.** The default path is under
   `.secrets/`, which is gitignored. `.gitignore` matches names, not content
   (THREAT_MODEL.md F-01), so the pre-commit hooks are the control that matters if
   the key's *content* ever lands in a tracked file.
2. **Loading refuses a group- or world-readable file**, the same rule ssh applies
   to private keys. A key that every local user can read is not a secret.
3. **`kid` is the RFC 7638 JWK thumbprint**, not a counter or a name. It is derived
   from the public key itself, so a verifier can never be told a `kid` that points
   at a different key than the one it names.
"""

import base64
import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

#: Generated keys are 3072-bit (NIST SP 800-57: ~128-bit security). Loading
#: accepts down to 2048, the floor RFC 7518 sets for RS256, so a key generated
#: elsewhere still loads; anything smaller is refused outright.
GENERATED_KEY_BITS: Final = 3072
MIN_KEY_BITS: Final = 2048

SIGNING_ALGORITHM: Final = "RS256"

#: Permission bits that must be clear on the key file: everything for group and other.
_FORBIDDEN_MODE_BITS: Final = stat.S_IRWXG | stat.S_IRWXO


class SigningKeyError(Exception):
    """The signing key is missing, weak, or exposed. The AS must not start."""


def _b64url_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class SigningKey:
    private_key: rsa.RSAPrivateKey
    kid: str

    @classmethod
    def from_private_key(cls, private_key: rsa.RSAPrivateKey) -> "SigningKey":
        if private_key.key_size < MIN_KEY_BITS:
            msg = f"RSA key is {private_key.key_size} bits; minimum is {MIN_KEY_BITS}"
            raise SigningKeyError(msg)
        return cls(private_key=private_key, kid=jwk_thumbprint(private_key.public_key()))

    def public_jwk(self) -> dict[str, str]:
        numbers = self.private_key.public_key().public_numbers()
        return {
            "kty": "RSA",
            "n": _b64url_uint(numbers.n),
            "e": _b64url_uint(numbers.e),
            "kid": self.kid,
            "alg": SIGNING_ALGORITHM,
            "use": "sig",
        }

    def jwks(self) -> dict[str, list[dict[str, str]]]:
        return {"keys": [self.public_jwk()]}


def jwk_thumbprint(public_key: rsa.RSAPublicKey) -> str:
    """RFC 7638 thumbprint: SHA-256 over the required members, sorted, no whitespace."""
    numbers = public_key.public_numbers()
    canonical = json.dumps(
        {"e": _b64url_uint(numbers.e), "kty": "RSA", "n": _b64url_uint(numbers.n)},
        separators=(",", ":"),
        sort_keys=True,
    )
    digest = hashlib.sha256(canonical.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def generate_key_file(path: Path) -> SigningKey:
    """Write a new PKCS#8 private key to `path`, mode 0600, refusing to overwrite.

    `O_EXCL` makes "refuse to overwrite" atomic, and the mode is set at creation
    rather than chmod-ed afterwards, so there is no window where the file exists
    with the umask's permissions.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=GENERATED_KEY_BITS)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(pem)
    return SigningKey.from_private_key(private_key)


def load_key_file(path: Path) -> SigningKey:
    """Load the signing key, refusing one that is missing, exposed, or weak."""
    try:
        mode = path.stat().st_mode
    except FileNotFoundError:
        msg = f"signing key not found at {path}; generate one with `python -m rlas keygen`"
        raise SigningKeyError(msg) from None
    if mode & _FORBIDDEN_MODE_BITS:
        msg = f"signing key {path} is accessible to group/other (mode {stat.filemode(mode)})"
        raise SigningKeyError(msg)

    private_key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(private_key, rsa.RSAPrivateKey):
        msg = f"signing key {path} is not an RSA key"
        raise SigningKeyError(msg)
    return SigningKey.from_private_key(private_key)
