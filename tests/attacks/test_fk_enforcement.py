"""SQLite foreign key enforcement is OFF by default.

PLAN.md step:  1
Category:      data integrity (no OWASP MCP id -- this one is upstream of authz)

Every test here was first run against a raw, unhardened engine and observed to
corrupt data successfully. The `unhardened_engine` fixture preserves that
vulnerable configuration permanently so the control stays proven, rather than
the suite merely asserting that today's code happens to behave.

`rlapi.db.create_db_engine` has no switch to disable enforcement on purpose --
the vulnerable engine is built here, in the tests, so the shipped API carries no
footgun.
"""

import sqlite3
from pathlib import Path

import pytest
from sqlalchemy import Engine, create_engine, insert, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.pool import StaticPool

from rlapi.db import HARDENING_PRAGMAS, assert_hardened, create_db_engine, effective_pragmas
from rlapi.models import Base, Order, OrderItem, OrderStatus, Product, User

MEMORY_URL = "sqlite://"


@pytest.fixture
def hardened_engine() -> Engine:
    """What the application actually ships."""
    engine = create_db_engine(MEMORY_URL)
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def unhardened_engine() -> Engine:
    """Stock SQLAlchemy with no `connect` listener -- i.e. the bug."""
    engine = create_engine(MEMORY_URL, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return engine


def _seed(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(insert(User).values(id=1, email="a@example.test", role="customer"))
        conn.execute(insert(Product).values(id=1, sku="SKU-1", name="Widget", price_cents=500))
        conn.execute(insert(Order).values(id=1, customer_id=1, status=OrderStatus.DRAFT))


# --------------------------------------------------------------------------
# The default, demonstrated three ways
# --------------------------------------------------------------------------


def test_stock_sqlite_does_not_enforce_foreign_keys() -> None:
    """No SQLAlchemy involved: this is SQLite's own default, not an ORM quirk."""
    conn = sqlite3.connect(":memory:")
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 0

    conn.execute("CREATE TABLE parent (id INTEGER PRIMARY KEY)")
    conn.execute("CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id REFERENCES parent(id))")
    # Parent 99999 does not exist. This silently succeeds.
    conn.execute("INSERT INTO child (id, parent_id) VALUES (1, 99999)")
    assert conn.execute("SELECT parent_id FROM child").fetchone()[0] == 99999


def test_check_constraints_are_enforced_by_default_but_foreign_keys_are_not() -> None:
    """The asymmetry that makes this trap easy to walk into.

    Both are declared the same way in DDL. One is enforced out of the box and
    one is not, so a schema that looks fully constrained is only half enforced.
    """
    conn = sqlite3.connect(":memory:")
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 0
    assert conn.execute("PRAGMA ignore_check_constraints").fetchone()[0] == 0

    conn.execute(
        "CREATE TABLE t ("
        "  id INTEGER PRIMARY KEY,"
        "  parent_id REFERENCES t(id),"
        "  qty INTEGER CHECK (qty > 0)"
        ")"
    )
    # CHECK: enforced.
    with pytest.raises(sqlite3.IntegrityError, match="CHECK constraint failed"):
        conn.execute("INSERT INTO t (id, parent_id, qty) VALUES (1, NULL, 0)")
    # FOREIGN KEY: not enforced.
    conn.execute("INSERT INTO t (id, parent_id, qty) VALUES (2, 99999, 1)")


@pytest.mark.attack
def test_orphan_order_item_is_accepted_without_hardening(unhardened_engine: Engine) -> None:
    """The exploit: a line item pointing at an order that does not exist."""
    _seed(unhardened_engine)
    with unhardened_engine.begin() as conn:
        conn.execute(
            insert(OrderItem).values(order_id=99999, product_id=1, qty=1, unit_price_cents=500)
        )
        orphan = conn.execute(select(OrderItem.order_id)).scalar_one()
    assert orphan == 99999, "expected the unhardened engine to accept an orphan row"


@pytest.mark.attack
def test_referenced_product_can_be_deleted_without_hardening(unhardened_engine: Engine) -> None:
    """RESTRICT is declared on order_items.product_id and ignored anyway."""
    _seed(unhardened_engine)
    with unhardened_engine.begin() as conn:
        conn.execute(
            insert(OrderItem).values(order_id=1, product_id=1, qty=1, unit_price_cents=500)
        )
        conn.execute(text("DELETE FROM products WHERE id = 1"))
        # The line item survives, now pointing at nothing. Order history is
        # silently corrupt: the item has a product_id that resolves to no row.
        dangling = conn.execute(select(OrderItem.product_id)).scalar_one()
        assert dangling == 1
        assert conn.execute(select(Product)).first() is None


# --------------------------------------------------------------------------
# The fix
# --------------------------------------------------------------------------


def test_hardening_pragmas_are_in_force(hardened_engine: Engine) -> None:
    assert effective_pragmas(hardened_engine, "foreign_keys") == {"foreign_keys": 1}
    assert_hardened(hardened_engine)


def test_assert_hardened_rejects_an_unhardened_engine(unhardened_engine: Engine) -> None:
    """The startup check must actually fail, not just exist."""
    with pytest.raises(RuntimeError, match="hardening not in force"):
        assert_hardened(unhardened_engine)


@pytest.mark.attack
def test_orphan_order_item_is_rejected_when_hardened(hardened_engine: Engine) -> None:
    _seed(hardened_engine)
    with (
        pytest.raises(IntegrityError, match="FOREIGN KEY constraint failed"),
        hardened_engine.begin() as conn,
    ):
        conn.execute(
            insert(OrderItem).values(order_id=99999, product_id=1, qty=1, unit_price_cents=500)
        )


@pytest.mark.attack
def test_referenced_product_cannot_be_deleted_when_hardened(hardened_engine: Engine) -> None:
    _seed(hardened_engine)
    with hardened_engine.begin() as conn:
        conn.execute(
            insert(OrderItem).values(order_id=1, product_id=1, qty=1, unit_price_cents=500)
        )
    with (
        pytest.raises(IntegrityError, match="FOREIGN KEY constraint failed"),
        hardened_engine.begin() as conn,
    ):
        conn.execute(text("DELETE FROM products WHERE id = 1"))


def test_cascade_removes_items_with_their_order(hardened_engine: Engine) -> None:
    """CASCADE on order_items.order_id, verified rather than assumed.

    Only observable with enforcement on: without it, neither CASCADE nor
    RESTRICT does anything at all.
    """
    _seed(hardened_engine)
    with hardened_engine.begin() as conn:
        conn.execute(
            insert(OrderItem).values(order_id=1, product_id=1, qty=1, unit_price_cents=500)
        )
    with hardened_engine.begin() as conn:
        conn.execute(text("DELETE FROM orders WHERE id = 1"))
    with hardened_engine.connect() as conn:
        assert conn.execute(select(OrderItem)).first() is None


# --------------------------------------------------------------------------
# The two traps that make this control easy to get wrong
# --------------------------------------------------------------------------


@pytest.mark.attack
def test_pragma_is_silently_ignored_inside_a_transaction() -> None:
    """Why the `connect` event is the only correct hook.

    Setting the pragma from inside a transaction does nothing **and raises no
    error**. Any attempt to harden via `Session.execute` or `engine.execute`
    lands here, because SQLAlchemy has already opened a transaction -- the code
    looks correct, the pragma reports success, and enforcement stays off.
    """
    conn = sqlite3.connect(":memory:", isolation_level=None)
    conn.execute("BEGIN")
    conn.execute("PRAGMA foreign_keys = ON")  # no-op, no exception
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 0
    conn.execute("COMMIT")
    # Outside the transaction it takes effect.
    conn.execute("PRAGMA foreign_keys = ON")
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


@pytest.mark.attack
def test_enforcement_is_per_connection_not_per_database() -> None:
    """A second connection to the same file starts with enforcement OFF.

    This is the pooled-application failure mode: hardening one connection at
    startup leaves every subsequent one unprotected. It is also why
    `create_db_engine` registers a listener instead of running the pragmas once.
    """
    engine = create_engine(MEMORY_URL, poolclass=StaticPool)
    with engine.connect() as conn:
        conn.exec_driver_sql("PRAGMA foreign_keys = ON")
        assert conn.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1

    raw = sqlite3.connect(":memory:")
    assert raw.execute("PRAGMA foreign_keys").fetchone()[0] == 0, (
        "a fresh connection must not inherit another connection's pragma"
    )


def test_journal_mode_is_persistent_unlike_the_others(tmp_path: Path) -> None:
    """WAL is stored in the database file; `foreign_keys` is not.

    Worth knowing when reasoning about what a new connection inherits: exactly
    one of our four hardening pragmas survives reconnection.
    """
    db = tmp_path / "t.db"
    engine = create_db_engine(f"sqlite:///{db}")
    Base.metadata.create_all(engine)
    assert effective_pragmas(engine, "journal_mode") == {"journal_mode": "wal"}
    engine.dispose()

    raw = sqlite3.connect(db)
    assert raw.execute("PRAGMA journal_mode").fetchone()[0] == "wal"  # persisted
    assert raw.execute("PRAGMA foreign_keys").fetchone()[0] == 0  # did not persist


def test_every_hardening_pragma_is_a_literal() -> None:
    """Pragmas take no bound parameters, so these must never be built from input."""
    for pragma in HARDENING_PRAGMAS:
        assert pragma.startswith("PRAGMA ")
        assert "{" not in pragma
        assert "%" not in pragma


def test_effective_pragmas_rejects_names_outside_the_allowlist(hardened_engine: Engine) -> None:
    """The control ruff's S608 will never remind us to keep (see db.py)."""
    with pytest.raises(ValueError, match="non-allowlisted pragma"):
        effective_pragmas(hardened_engine, "foreign_keys; ATTACH DATABASE '/etc/passwd' AS x")
