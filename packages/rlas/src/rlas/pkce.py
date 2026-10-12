"""PKCE (RFC 7636) verification.

!!! DELIBERATELY VULNERABLE -- PLAN.md step 3, "break" phase !!!

Two of step 3's four exploits live here:

- PKCE is *optional*: no `code_challenge` at /authorize means no check at /token,
  so a stolen code is redeemable by whoever holds it.
- `plain` is accepted, and is the RFC 7636 default when the method is omitted. With
  `plain` the challenge *is* the verifier, so anyone who saw the authorization
  request URL -- browser history, a proxy log, a Referer header -- holds it.
"""

import base64
import hashlib
import hmac
import re
from typing import Final

SUPPORTED_METHODS: Final = frozenset({"S256", "plain"})

#: RFC 7636 section 4.1: 43-128 characters from the unreserved set.
_VERIFIER_RE: Final = re.compile(r"[A-Za-z0-9\-._~]{43,128}")


def s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def verify(verifier: str | None, challenge: str | None, method: str | None) -> bool:
    """Does `verifier` answer the challenge recorded at /authorize?"""
    if challenge is None:
        return True  # no challenge recorded, nothing to check
    if verifier is None or not _VERIFIER_RE.fullmatch(verifier):
        return False
    if (method or "plain") == "plain":
        return hmac.compare_digest(verifier, challenge)
    return hmac.compare_digest(s256(verifier), challenge)
