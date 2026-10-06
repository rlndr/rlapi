"""Shared fixtures.

The API is exercised against an in-memory SQLite database built by
`create_db_engine`, so step 1's hardening is in force for every test here --
foreign keys enforced, CHECK constraints live. That matters for step 2: some of
what the mass-assignment exploit can do is caught by the database and some is
not, and the difference is only visible if the database is the real one.

`Base.metadata.create_all` is used rather than running Alembic, for speed.
`tests/unit/test_migrations.py` is what checks that the migrations produce this
same schema; keeping those two concerns apart means a schema drift shows up as
one clear failure rather than breaking every test at once.

**Why a temp file and not `:memory:`.** `TestClient` runs the ASGI app in its
own thread, and an in-memory database needs `StaticPool` -- one connection,
which `sqlite3` refuses to share across threads. The fix is not to relax
`check_same_thread`: a file-backed database uses the ordinary pool, so each
thread opens its own connection and every one of them has to be hardened
separately. That is precisely the property F-03 is about ("per connection, not
per database"), so this fixture exercises the listener the way production does
instead of hiding behind a single shared connection.
"""

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from rlapi.app import create_app
from rlapi.db import create_db_engine, create_session_factory
from rlapi.models import Base, Order, OrderItem, Product, Role, User


@pytest.fixture
def engine(tmp_path: Path) -> Iterator[Engine]:
    engine = create_db_engine(f"sqlite:///{tmp_path / 'test.db'}")
    Base.metadata.create_all(engine)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def session_factory(engine: Engine) -> sessionmaker[Session]:
    return create_session_factory(engine)


@pytest.fixture
def seeded(session_factory: sessionmaker[Session]) -> dict[str, int]:
    """One user per role, two products, one order. Returns the ids.

    Deliberately includes an `admin` row: the SQL injection exploit exfiltrates
    the users table, and the interesting part of that payload is the `role`
    column, not the email.
    """
    with session_factory.begin() as session:
        users = [User(email=f"{role.value}@example.test", role=role) for role in Role]
        widget = Product(sku="SKU-WIDGET", name="Widget", price_cents=1999, stock_qty=10)
        gadget = Product(sku="SKU-GADGET", name="Gadget", price_cents=4950, stock_qty=3)
        session.add_all([*users, widget, gadget])
        session.flush()

        order = Order(customer_id=users[0].id, total_cents=1999)
        order.items.append(
            OrderItem(product_id=widget.id, qty=1, unit_price_cents=widget.price_cents)
        )
        session.add(order)
        session.flush()

        return {
            "customer_id": users[0].id,
            "admin_id": users[-1].id,
            "widget_id": widget.id,
            "gadget_id": gadget.id,
            "order_id": order.id,
        }


@pytest.fixture
def app(session_factory: sessionmaker[Session], engine: Engine) -> FastAPI:
    return create_app(session_factory, engine=engine)


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client
