"""Model-level integrity constraints.

These CHECK constraints are the **backstop**, not the control. Step 11's
negative-quantity and price-tampering attacks must be rejected by the API's
input models long before SQL is emitted. What these tests guarantee is that a
bug in that layer produces an error instead of corrupt data.

Worth stating plainly because it is easy to over-read: a passing test here does
not mean the API is safe. It means the database will not silently accept
nonsense if the API is not.

Note the SQL below is all literal. Parametrising a *column name* would require
interpolation, and ruff's S608 does not flag every interpolated statement
(see `rlapi.db._READABLE_PRAGMAS`), so the habit of writing literals is worth
keeping even in tests.
"""

from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import Engine, Executable, insert, text
from sqlalchemy.exc import IntegrityError

from rlapi.db import create_db_engine
from rlapi.models import Base, Order, OrderItem, OrderStatus, Product, Role, User, utcnow

MEMORY_URL = "sqlite://"


@pytest.fixture
def engine() -> Engine:
    eng = create_db_engine(MEMORY_URL)
    Base.metadata.create_all(eng)
    with eng.begin() as conn:
        conn.execute(insert(User).values(id=1, email="c@example.test", role=Role.CUSTOMER))
        conn.execute(
            insert(Product).values(id=1, sku="SKU-1", name="Widget", price_cents=500, stock_qty=10)
        )
        conn.execute(insert(Order).values(id=1, customer_id=1, status=OrderStatus.DRAFT))
    return eng


def expect_integrity_error(engine: Engine, statement: Executable, pattern: str) -> None:
    """Assert `statement` is refused by the database with a matching message."""
    with pytest.raises(IntegrityError, match=pattern), engine.begin() as conn:
        conn.execute(statement)


def scalar(engine: Engine, statement: str) -> Any:
    with engine.connect() as conn:
        return conn.execute(text(statement)).scalar_one()


# --------------------------------------------------------------------------
# CHECK constraints
# --------------------------------------------------------------------------

CHECK_FAILED = "CHECK constraint failed"


@pytest.mark.parametrize(
    "statement",
    [
        pytest.param("UPDATE products SET price_cents = -1 WHERE id = 1", id="negative-price"),
        pytest.param("UPDATE products SET stock_qty = -1 WHERE id = 1", id="negative-stock"),
        pytest.param("UPDATE orders SET total_cents = -1 WHERE id = 1", id="negative-total"),
        pytest.param(
            "UPDATE products SET stock_qty = stock_qty - 999999 WHERE id = 1",
            id="stock-decrement-underflow",
        ),
    ],
)
def test_negative_money_and_quantities_are_rejected(engine: Engine, statement: str) -> None:
    """`stock-decrement-underflow` is step 11's `adjust_stock(delta=-999999)`."""
    expect_integrity_error(engine, text(statement), CHECK_FAILED)


@pytest.mark.parametrize("qty", [0, -1, -999])
def test_order_item_quantity_must_be_positive(engine: Engine, qty: int) -> None:
    """Zero is rejected as well as negative -- a zero-quantity line is nonsense."""
    expect_integrity_error(
        engine,
        insert(OrderItem).values(order_id=1, product_id=1, qty=qty, unit_price_cents=500),
        CHECK_FAILED,
    )


def test_order_item_unit_price_cannot_be_negative(engine: Engine) -> None:
    expect_integrity_error(
        engine,
        insert(OrderItem).values(order_id=1, product_id=1, qty=1, unit_price_cents=-1),
        CHECK_FAILED,
    )


def test_valid_order_item_is_accepted(engine: Engine) -> None:
    """The constraints must not be so tight that legitimate writes fail."""
    with engine.begin() as conn:
        conn.execute(
            insert(OrderItem).values(order_id=1, product_id=1, qty=2, unit_price_cents=500)
        )
    assert scalar(engine, "SELECT qty FROM order_items") == 2


# --------------------------------------------------------------------------
# Uniqueness
# --------------------------------------------------------------------------

UNIQUE_FAILED = "UNIQUE constraint failed"


def test_email_is_unique(engine: Engine) -> None:
    expect_integrity_error(
        engine,
        insert(User).values(id=2, email="c@example.test", role=Role.CLERK),
        UNIQUE_FAILED,
    )


def test_sku_is_unique(engine: Engine) -> None:
    expect_integrity_error(
        engine, insert(Product).values(id=2, sku="SKU-1", name="Clone"), UNIQUE_FAILED
    )


# --------------------------------------------------------------------------
# Timestamps
# --------------------------------------------------------------------------


def test_utcnow_is_timezone_aware() -> None:
    """Naive datetimes are indistinguishable from local time once stored.

    Step 4 compares token `exp`/`nbf` against wall clock; a naive value there
    is a bug whose sign depends on the host's timezone.
    """
    now = utcnow()
    assert now.tzinfo is not None
    assert now.utcoffset() == datetime.now(UTC).utcoffset()


def test_created_at_is_populated_without_being_supplied(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(insert(User).values(id=3, email="d@example.test", role=Role.CLERK))
    assert scalar(engine, "SELECT created_at FROM users WHERE id = 3") is not None


# --------------------------------------------------------------------------
# Denormalised price
# --------------------------------------------------------------------------


def test_order_item_price_survives_a_product_price_change(engine: Engine) -> None:
    """`unit_price_cents` records the price at order time, by design.

    An audit property as much as a correctness one: if changing a product's
    price rewrote historical order totals, the order history would not be
    evidence of anything.
    """
    with engine.begin() as conn:
        conn.execute(
            insert(OrderItem).values(order_id=1, product_id=1, qty=1, unit_price_cents=500)
        )
    with engine.begin() as conn:
        conn.execute(text("UPDATE products SET price_cents = 9999 WHERE id = 1"))

    assert scalar(engine, "SELECT unit_price_cents FROM order_items") == 500
    assert scalar(engine, "SELECT price_cents FROM products WHERE id = 1") == 9999
