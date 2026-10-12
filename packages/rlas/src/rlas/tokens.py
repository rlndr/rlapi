"""RFC 9068 JWT access tokens.

`typ: at+jwt` in the header is what distinguishes an access token from an ID
token or any other JWT signed by the same key. RFC 9068 section 4 requires
resource servers to check it. Step 4's validator can then reject a different
kind of JWT presented as a bearer token.

`aud` is the single `resource` the client asked for (RFC 8707), never a list
and never a default. A token without a specific audience is a token every
resource server would have to accept, which is the passthrough problem
step 4 exists to close.
"""

import secrets
from collections.abc import Sequence
from datetime import datetime, timedelta

import jwt

from rlas.keys import SIGNING_ALGORITHM, SigningKey


def mint_access_token(
    key: SigningKey,
    *,
    issuer: str,
    sub: str,
    audience: str,
    client_id: str,
    scope: Sequence[str],
    roles: Sequence[str],
    ttl: timedelta,
    now: datetime,
) -> str:
    claims = {
        "iss": issuer,
        "sub": sub,
        "aud": audience,
        "client_id": client_id,
        "scope": " ".join(scope),
        "roles": list(roles),
        "iat": int(now.timestamp()),
        "exp": int((now + ttl).timestamp()),
        "jti": secrets.token_urlsafe(16),
    }
    return jwt.encode(
        claims,
        key.private_key,
        algorithm=SIGNING_ALGORITHM,
        headers={"kid": key.kid, "typ": "at+jwt"},
    )
