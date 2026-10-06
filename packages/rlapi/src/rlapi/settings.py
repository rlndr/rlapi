"""Runtime configuration.

The database URL comes from the environment and has no production default --
`DEFAULT_DATABASE_URL` is a local file, which is safe to commit precisely
because it is useless to an attacker. By step 18 this value is a real
connection string; the habit of never writing one into a file under version
control is cheaper to build now than to retrofit then.

These constants lived in `migrations/env.py` until step 2. Two definitions of
"where is the database" is one too many: the migration runner and the
application must agree, or migrations harden a different database than the one
being served.
"""

import os
from typing import Final

DATABASE_URL_ENV_VAR: Final = "RLAPI_DATABASE_URL"
DEFAULT_DATABASE_URL: Final = "sqlite:///rlapi.db"


def database_url(default: str = DEFAULT_DATABASE_URL) -> str:
    """Resolve the target database, environment first."""
    return os.environ.get(DATABASE_URL_ENV_VAR) or default
