"""`users.role` is an authorization input, so the column must be constrained.

PLAN.md step:  1
OWASP:         MCP07 (precursor -- the data authz decisions will be read from)

Found while verifying step 1's DDL rather than from the plan: declaring a
column as `Enum(Role)` does **not** constrain it. SQLAlchemy's
`Enum.create_constraint` has defaulted to `False` since 1.4, so the emitted DDL
was a bare `VARCHAR(8)` with no CHECK -- and SQLite does not enforce VARCHAR
length either, so the column accepted arbitrary text of any length.

The `unconstrained_*` fixtures preserve the vulnerable schema so the control
stays proven. Step 5 compares a token's role claim against this column; these
tests are what stop that comparison being made against attacker-chosen data.
"""

import enum

import pytest
from sqlalchemy import Column as Col
from sqlalchemy import Engine, Enum, MetaData, String, Table, insert, text
from sqlalchemy.exc import IntegrityError, StatementError

from rlapi.db import create_db_engine
from rlapi.models import Base, Role, User, strict_enum

MEMORY_URL = "sqlite://"

#: Values an attacker (or a bug) might try to write into a role column.
HOSTILE_ROLES = [
    "root",
    "superuser",
    "ADMIN",  # right word, wrong case
    "admin ",  # trailing space: not == "admin", but may survive TRIM/LIKE checks
    " admin",
    "",
    "customer,admin",
    "a" * 64,  # far longer than VARCHAR(8)
]


@pytest.fixture
def hardened_engine() -> Engine:
    engine = create_db_engine(MEMORY_URL)
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def unconstrained_engine() -> Engine:
    """The schema as it was before the fix: `Enum` without `create_constraint`."""
    metadata = MetaData()
    Table(
        "users_unconstrained",
        metadata,
        Col("id", primary_key=True, type_=String(10)),
        Col("email", String(320), nullable=False),
        # This is the bug, verbatim: no create_constraint, so no CHECK is emitted.
        Col("role", Enum(Role, name="role_bad", native_enum=False), nullable=False),
    )
    engine = create_db_engine(MEMORY_URL)
    metadata.create_all(engine)
    return engine


# --------------------------------------------------------------------------
# The vulnerability
# --------------------------------------------------------------------------


def test_enum_without_create_constraint_emits_no_check(unconstrained_engine: Engine) -> None:
    engine = unconstrained_engine
    with engine.connect() as conn:
        ddl: str = conn.execute(
            text("SELECT sql FROM sqlite_master WHERE name = 'users_unconstrained'")
        ).scalar_one()
    assert "VARCHAR" in ddl
    assert "CHECK" not in ddl, "expected the pre-fix schema to have no CHECK constraint"


@pytest.mark.attack
@pytest.mark.mcp07
@pytest.mark.parametrize("hostile", HOSTILE_ROLES)
def test_unconstrained_column_accepts_arbitrary_roles(
    unconstrained_engine: Engine, hostile: str
) -> None:
    """The exploit: write any string into the column authorization reads."""
    engine = unconstrained_engine
    with engine.begin() as conn:
        conn.execute(
            text("INSERT INTO users_unconstrained (id, email, role) VALUES (:i, :e, :r)"),
            {"i": "1", "e": "a@t.test", "r": hostile},
        )
        stored: str = conn.execute(text("SELECT role FROM users_unconstrained")).scalar_one()
    assert stored == hostile


def test_sqlite_does_not_enforce_varchar_length(unconstrained_engine: Engine) -> None:
    """Why `VARCHAR(8)` was never a limit.

    SQLite treats a length modifier as advisory. A 64-character value goes into
    a VARCHAR(8) column without complaint, so column width is not a control on
    any SQLite-backed system.
    """
    engine = unconstrained_engine
    long_value = "a" * 64
    with engine.begin() as conn:
        conn.execute(
            text("INSERT INTO users_unconstrained (id, email, role) VALUES ('1','a@t.test',:r)"),
            {"r": long_value},
        )
        assert len(conn.execute(text("SELECT role FROM users_unconstrained")).scalar_one()) == 64


# --------------------------------------------------------------------------
# The fix
# --------------------------------------------------------------------------


def test_role_column_has_a_check_constraint(hardened_engine: Engine) -> None:
    with hardened_engine.connect() as conn:
        ddl: str = conn.execute(
            text("SELECT sql FROM sqlite_master WHERE name = 'users'")
        ).scalar_one()
    assert "CHECK (role IN ('customer', 'clerk', 'manager', 'admin'))" in ddl
    # Exactly one. Alembic autogenerate renders the enum CHECK explicitly in
    # addition to the implicit one, which produced three identical constraints
    # before the migration was reviewed by hand.
    assert ddl.count("CHECK") == 1


@pytest.mark.attack
@pytest.mark.mcp07
@pytest.mark.parametrize("hostile", HOSTILE_ROLES)
def test_hardened_column_rejects_arbitrary_roles(hardened_engine: Engine, hostile: str) -> None:
    with (
        pytest.raises(IntegrityError, match="CHECK constraint failed"),
        hardened_engine.begin() as conn,
    ):
        conn.execute(
            text(
                "INSERT INTO users (id, email, role, created_at) "
                "VALUES (1, :e, :r, CURRENT_TIMESTAMP)"
            ),
            {"e": "a@t.test", "r": hostile},
        )


def test_orm_layer_rejects_unknown_role_strings(hardened_engine: Engine) -> None:
    """`validate_strings=True` catches it before SQL is even emitted.

    Two independent layers: the ORM refuses the value, and the CHECK constraint
    refuses it if the ORM is bypassed (raw SQL, a migration, sqlite3 CLI).
    """
    with pytest.raises(StatementError), hardened_engine.begin() as conn:
        conn.execute(insert(User).values(id=1, email="a@t.test", role="root"))


# --------------------------------------------------------------------------
# Storage format: values, not member names
# --------------------------------------------------------------------------


def test_enum_is_stored_as_its_value_not_its_member_name(hardened_engine: Engine) -> None:
    """`Role.CUSTOMER` must land as `'customer'`, not `'CUSTOMER'`.

    SQLAlchemy stores `member.name` by default. Left alone, the database would
    hold `'CUSTOMER'` while the JWT `roles` claim, the API wire format and this
    codebase all say `'customer'` -- a mismatch that step 5's authorization
    comparison would hit silently.
    """
    with hardened_engine.begin() as conn:
        conn.execute(insert(User).values(id=1, email="a@t.test", role=Role.CUSTOMER))
        raw: str = conn.execute(text("SELECT role FROM users WHERE id = 1")).scalar_one()
    assert raw == "customer"
    assert raw != "CUSTOMER"


def test_member_names_are_rejected_as_values(hardened_engine: Engine) -> None:
    """Guard against the mismatch reappearing: 'CUSTOMER' must not be storable."""
    with (
        pytest.raises(IntegrityError, match="CHECK constraint failed"),
        hardened_engine.begin() as conn,
    ):
        conn.execute(
            text(
                "INSERT INTO users (id, email, role, created_at) "
                "VALUES (1, 'a@t.test', 'CUSTOMER', CURRENT_TIMESTAMP)"
            )
        )


def test_strict_enum_covers_every_member_of_the_enum() -> None:
    """A new Role member must reach the CHECK constraint automatically.

    Guards the realistic regression: someone adds `Role.AUDITOR` and the
    constraint silently keeps the old four values.
    """

    class Extended(enum.StrEnum):
        ONE = "one"
        TWO = "two"

    column_type = strict_enum(Extended, "extended")
    assert set(column_type.enums) == {"one", "two"}
    assert column_type.create_constraint is True
