"""PKCE (RFC 7636) verification. S256 only.

There is deliberately no `plain` branch. With `plain` the challenge *is* the
verifier, so anyone who saw the authorization request URL -- browser history,
a proxy log -- holds it. Worse, RFC 7636 makes `plain` the default when the
method is omitted. At the step 3 break, a client that hashed its challenge
correctly but forgot `code_challenge_method=S256` had its own verifier refused,
while a thief presenting the *challenge* from the URL got a token
(THREAT_MODEL.md F-16).

Requiring PKCE is `/authorize`'s job: a request without an S256 challenge never
produces a code. `verify` takes the challenge as `str`, not `str | None`, so the
type checker rejects any path that reaches /token without one recorded.
"""

import base64
import hashlib
import hmac
import re
from typing import Final

SUPPORTED_METHODS: Final = frozenset({"S256"})

#: RFC 7636 section 4.1: 43-128 characters from the unreserved set.
_VERIFIER_RE: Final = re.compile(r"[A-Za-z0-9\-._~]{43,128}")


def s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def verify(verifier: str | None, challenge: str) -> bool:
    """Does `verifier` hash to the S256 challenge recorded at /authorize?"""
    if verifier is None or not _VERIFIER_RE.fullmatch(verifier):
        return False
    return hmac.compare_digest(s256(verifier), challenge)
