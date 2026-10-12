"""Runtime configuration.

Paths default under `.secrets/`, which is gitignored. The signing key and the
user file both live there, and neither has a usable default *value*: if they are
missing the AS refuses to start rather than generating something on the fly. A
key minted silently at boot would also be rotated silently on every restart,
invalidating every token in flight with no record of why.
"""

import os
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Final

ISSUER_ENV_VAR: Final = "RLAS_ISSUER"
SIGNING_KEY_ENV_VAR: Final = "RLAS_SIGNING_KEY_FILE"
USERS_ENV_VAR: Final = "RLAS_USERS_FILE"
CLIENTS_ENV_VAR: Final = "RLAS_CLIENTS_FILE"

DEFAULT_ISSUER: Final = "http://127.0.0.1:9000"
DEFAULT_SIGNING_KEY_FILE: Final = ".secrets/rlas-signing-key.pem"
DEFAULT_USERS_FILE: Final = ".secrets/rlas-users.json"

#: The resource servers this AS will mint tokens for. A `resource` outside this
#: set is `invalid_target` (RFC 8707), so no token is ever issued for an
#: audience nobody validates.
DEFAULT_RESOURCES: Final = frozenset({"https://rlapi.local", "https://rlmcp.local"})

#: Step 5 owns the meaning of these. Until then the AS issues any of them to any
#: authenticated user who asks -- see PLAN.md section 0, open items.
DEFAULT_SCOPES: Final = frozenset(
    {"orders:read", "orders:write", "products:write", "stock:adjust", "users:admin"}
)


@dataclass(frozen=True)
class ServerConfig:
    issuer: str = DEFAULT_ISSUER
    resources: frozenset[str] = field(default=DEFAULT_RESOURCES)
    scopes: frozenset[str] = field(default=DEFAULT_SCOPES)
    access_token_ttl: timedelta = timedelta(minutes=10)
    #: OAuth 2.1 recommends a maximum code lifetime of 10 minutes. One is plenty
    #: for a redirect that happens in the same second.
    code_ttl: timedelta = timedelta(minutes=1)
    #: How long a rendered login form stays redeemable.
    login_ttl: timedelta = timedelta(minutes=5)
    refresh_token_ttl: timedelta = timedelta(hours=8)


def config_from_env() -> ServerConfig:
    return ServerConfig(issuer=os.environ.get(ISSUER_ENV_VAR) or DEFAULT_ISSUER)


def path_from_env(var: str, default: str) -> Path:
    return Path(os.environ.get(var) or default)
