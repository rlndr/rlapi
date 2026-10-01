"""The migration must produce exactly the schema the models declare.

Drift between `Base.metadata` and the migration chain is how a constraint ends
up in one and not the other -- the models look safe in review while the running
database is missing the CHECK. Step 1's enum finding was exactly this shape, so
it is worth a test rather than a habit.
"""

from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext

import rlapi
from rlapi.db import create_db_engine
from rlapi.models import Base

PACKAGE_ROOT = Path(rlapi.__file__).parent
MIGRATIONS_DIR = PACKAGE_ROOT / "migrations"
ALEMBIC_INI = PACKAGE_ROOT.parents[1] / "alembic.ini"


def _alembic_config(database_url: str) -> Config:
    config = Config(str(ALEMBIC_INI))
    # script_location in the ini is relative to packages/rlapi; resolve it so
    # the tests run from any working directory.
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def test_alembic_ini_pins_no_database_url() -> None:
    """Connection strings belong in the environment, not in version control."""
    raw = ALEMBIC_INI.read_text()
    active = [line for line in raw.splitlines() if line.strip().startswith("sqlalchemy.url")]
    assert active == [], f"alembic.ini should not pin a URL, found: {active}"


def test_exactly_one_migration_revision() -> None:
    """Step 1 ships a single initial revision; catches an accidental duplicate."""
    revisions = sorted((MIGRATIONS_DIR / "versions").glob("*.py"))
    assert len(revisions) == 1, [p.name for p in revisions]


def test_migration_matches_models(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Apply the migration chain, then assert zero diff against the models."""
    db = tmp_path / "drift.db"
    url = f"sqlite:///{db}"
    monkeypatch.setenv("RLAPI_DATABASE_URL", url)

    command.upgrade(_alembic_config(url), "head")

    engine = create_db_engine(url)
    try:
        with engine.connect() as conn:
            context = MigrationContext.configure(conn)
            diff = compare_metadata(context, Base.metadata)
    finally:
        engine.dispose()

    assert diff == [], f"schema drift between migration and models: {diff}"


def test_migration_is_reversible(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`downgrade base` must actually work.

    An initial migration with a broken downgrade is not noticed until the day
    someone needs it. SQLite's batch mode rebuilds tables, so reversibility is
    worth checking rather than assuming.
    """
    db = tmp_path / "rev.db"
    url = f"sqlite:///{db}"
    monkeypatch.setenv("RLAPI_DATABASE_URL", url)
    config = _alembic_config(url)

    command.upgrade(config, "head")
    engine = create_db_engine(url)
    try:
        with engine.connect() as conn:
            tables_at_head = set(Base.metadata.tables) & set(conn.dialect.get_table_names(conn))
        assert tables_at_head == set(Base.metadata.tables)
    finally:
        engine.dispose()

    command.downgrade(config, "base")
    engine = create_db_engine(url)
    try:
        with engine.connect() as conn:
            remaining = set(Base.metadata.tables) & set(conn.dialect.get_table_names(conn))
        assert remaining == set()
    finally:
        engine.dispose()
