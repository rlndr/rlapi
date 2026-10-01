"""Engine construction and SQLite hardening.

The whole point of this module is the `connect` event listener. SQLite disables
foreign key enforcement by default and the setting is **per connection**, so a
pooled application must apply it to every connection it opens, not once at
startup.

Two traps make this harder than it looks:

1. `PRAGMA foreign_keys` is a **no-op inside a transaction**, and SQLite raises
   no error when it is ignored. Issuing it through `engine.execute()` or a
   `Session` therefore appears to succeed while changing nothing, because
   SQLAlchemy has already opened a transaction. The `connect` event fires before
   any transaction exists, which is why it is the only correct hook.
2. Pragmas do not accept bound parameters, so these statements must be literals.
   They are constants here rather than f-strings so that nothing resembling
   user input can ever reach them.

Note the deliberate absence of an `enforce_foreign_keys=False` option. A flag
that disables an integrity control is a footgun in shipped code; the attack
suite demonstrates the unhardened behaviour by constructing its own raw engine
instead. See `tests/attacks/test_fk_enforcement.py`.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Final

from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.engine.interfaces import DBAPIConnection
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import ConnectionPoolEntry, StaticPool

#: Applied to every new connection. Order matters only in that `foreign_keys`
#: is the integrity control and comes first.
HARDENING_PRAGMAS: Final[tuple[str, ...]] = (
    # Integrity. OFF by default in SQLite -- the entire reason this module exists.
    "PRAGMA foreign_keys = ON",
    # Availability. Wait rather than raising "database is locked" immediately.
    "PRAGMA busy_timeout = 5000",
    # Concurrency. Readers do not block the writer. Persistent (stored in the
    # database file), unlike the others, which reset with every connection.
    "PRAGMA journal_mode = WAL",
    # Durability/performance tradeoff that is safe under WAL.
    "PRAGMA synchronous = NORMAL",
)

#: Pragmas whose effective value we assert after connecting, with the value
#: expected. `journal_mode` is excluded: it reports "memory" for in-memory
#: databases, where WAL does not apply.
_VERIFIED_PRAGMAS: Final[dict[str, int]] = {"foreign_keys": 1}

#: Allowlist for `effective_pragmas`. Pragmas cannot take bound parameters, so
#: reading one requires interpolating its name into the statement -- an
#: injection path if the name were ever caller-controlled.
#:
#: Worth knowing: ruff's S608 does **not** flag that interpolation. Its
#: heuristic matches SELECT/INSERT/UPDATE/DELETE, so `f"PRAGMA {name}"`,
#: `f"VACUUM {name}"` and `f"ATTACH DATABASE '{name}'"` all pass clean --
#: verified at step 1, and the last of those is a file read/write primitive.
#: This allowlist is therefore a control SAST will never remind us to keep.
_READABLE_PRAGMAS: Final[frozenset[str]] = frozenset(
    {
        "foreign_keys",
        "journal_mode",
        "busy_timeout",
        "synchronous",
        "ignore_check_constraints",
        "user_version",
    }
)


def _harden_sqlite_connection(
    dbapi_connection: DBAPIConnection,
    _connection_record: ConnectionPoolEntry,
) -> None:
    """Apply hardening pragmas to a freshly opened DBAPI connection."""
    cursor = dbapi_connection.cursor()
    try:
        for pragma in HARDENING_PRAGMAS:
            cursor.execute(pragma)
    finally:
        cursor.close()


def _is_memory_url(url: str) -> bool:
    return ":memory:" in url or "mode=memory" in url


def create_db_engine(url: str, *, echo: bool = False) -> Engine:
    """Build a hardened engine.

    Always registers the hardening listener. In-memory databases additionally
    get `StaticPool`, because the default pool would discard the connection and
    with it the entire database between checkouts.
    """
    if _is_memory_url(url):
        engine = create_engine(url, echo=echo, poolclass=StaticPool)
    else:
        engine = create_engine(url, echo=echo)

    event.listen(engine, "connect", _harden_sqlite_connection)
    return engine


def effective_pragmas(engine: Engine, *names: str) -> dict[str, int | str]:
    """Read back the pragma values actually in force on a pooled connection.

    Used by `assert_hardened` and reused in step 17's startup posture check.
    Reading rather than assuming matters here: the no-op-in-transaction
    behaviour means a pragma can appear to have been set without taking effect.

    Names are checked against `_READABLE_PRAGMAS` because the pragma name must
    be interpolated -- see that constant for why no linter will flag this.
    """
    wanted = names or tuple(_VERIFIED_PRAGMAS)
    unknown = sorted(set(wanted) - _READABLE_PRAGMAS)
    if unknown:
        msg = f"refusing to read non-allowlisted pragma(s): {unknown}"
        raise ValueError(msg)
    with engine.connect() as conn:
        return {name: conn.execute(text(f"PRAGMA {name}")).scalar_one() for name in wanted}


def assert_hardened(engine: Engine) -> None:
    """Fail loudly if the integrity pragmas are not in force.

    Call at startup. A silently unhardened engine is worse than a missing one:
    writes succeed and corruption accumulates without any error to notice.
    """
    actual = effective_pragmas(engine, *_VERIFIED_PRAGMAS)
    wrong = {k: actual[k] for k, v in _VERIFIED_PRAGMAS.items() if actual[k] != v}
    if wrong:
        msg = f"SQLite hardening not in force: {wrong} (expected {_VERIFIED_PRAGMAS})"
        raise RuntimeError(msg)


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """Transactional scope: commit on success, roll back on any exception."""
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
