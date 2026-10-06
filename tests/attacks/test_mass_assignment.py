"""Mass assignment: the client writes fields the server owns.

PLAN.md step 2, "break" phase. Every test here currently asserts that the
**exploit succeeds**, because the code under test is the deliberately lazy
version: one Pydantic model per entity for both directions, spread straight
into the ORM with `**payload.model_dump()`.

When the fix lands these assertions invert. Writing them this way round first
is the whole method -- a regression test that has never been seen to pass
against vulnerable code is only evidence that *something* returns 422.

Marked `mcp05` to match PLAN.md's category for step 2, though the sharper fit
is MCP07: what is actually wrong is that the API has no notion of which fields
a caller is permitted to write. Step 5 makes that explicit per role.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from rlapi.models import Order, OrderStatus, Product

pytestmark = [pytest.mark.attack, pytest.mark.mcp05]


def test_client_can_reassign_an_unreferenced_product_primary_key(
    client: TestClient, seeded: dict[str, int], session_factory: sessionmaker[Session]
) -> None:
    """`id` is in the input model, so it is writable.

    The gadget has no order items pointing at it, so nothing stops the
    reassignment. Compare the test below.
    """
    original = seeded["gadget_id"]

    response = client.patch(f"/products/{original}", json={"id": 9999})

    assert response.status_code == 200
    assert response.json()["id"] == 9999

    with session_factory() as session:
        assert session.get(Product, original) is None
        assert session.get(Product, 9999) is not None


def test_pk_reassignment_is_blocked_only_when_the_row_is_referenced(
    client: TestClient, seeded: dict[str, int]
) -> None:
    """Step 1's FK enforcement partially shields step 2's bug -- by accident.

    The widget *is* referenced by an order item with `ON DELETE RESTRICT`, so
    `UPDATE products SET id=9999` trips `FOREIGN KEY constraint failed` and the
    write fails. Worth being precise about what that means:

    - The API still **accepted** the field and issued the UPDATE. The
      application-layer flaw is entirely present; the database caught it.
    - The protection covers exactly those products that happen to have order
      history. "Has this row been ordered yet" is not a security boundary, and
      the test above shows the other half of the catalogue is wide open.
    - Deployed, this surfaces as an unhandled 500, not a 4xx.

    This is the kind of control worth naming as incidental in the ledger
    (THREAT_MODEL.md F-09) rather than counting as mitigation.
    """
    with pytest.raises(IntegrityError, match="FOREIGN KEY constraint failed"):
        client.patch(f"/products/{seeded['widget_id']}", json={"id": 9999})


def test_client_can_create_an_order_already_shipped_and_free(
    client: TestClient, seeded: dict[str, int]
) -> None:
    """`status` and `total_cents` are server-derived, and accepted anyway.

    This is the one that matters. The order workflow exists to make a customer
    pay before goods move; here a caller skips straight to the end state and
    sets the price to zero in the same request.
    """
    response = client.post(
        "/orders",
        json={
            "customer_id": seeded["customer_id"],
            "status": "shipped",
            "total_cents": 0,
            "items": [{"product_id": seeded["gadget_id"], "qty": 1, "unit_price_cents": 0}],
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "shipped"
    assert body["total_cents"] == 0


def test_client_can_set_a_unit_price_the_catalogue_never_offered(
    client: TestClient, seeded: dict[str, int]
) -> None:
    """`unit_price_cents` must be read from the product, not from the request."""
    response = client.post(
        "/orders",
        json={
            "customer_id": seeded["customer_id"],
            "items": [{"product_id": seeded["gadget_id"], "qty": 2, "unit_price_cents": 1}],
        },
    )

    assert response.status_code == 201
    assert response.json()["items"][0]["unit_price_cents"] == 1


def test_client_can_zero_an_existing_order_total(
    client: TestClient, seeded: dict[str, int], session_factory: sessionmaker[Session]
) -> None:
    response = client.patch(f"/orders/{seeded['order_id']}", json={"total_cents": 0})

    assert response.status_code == 200
    with session_factory() as session:
        order = session.get(Order, seeded["order_id"])
        assert order is not None
        assert order.total_cents == 0


def test_client_can_advance_order_status_arbitrarily(
    client: TestClient, seeded: dict[str, int]
) -> None:
    """No state machine: draft -> shipped in one hop, skipping placed and paid."""
    response = client.patch(f"/orders/{seeded['order_id']}", json={"status": "shipped"})

    assert response.status_code == 200
    assert response.json()["status"] == OrderStatus.SHIPPED.value


def test_unknown_fields_are_silently_ignored_rather_than_rejected(
    client: TestClient, seeded: dict[str, int]
) -> None:
    """Pydantic defaults to `extra="ignore"`, which hides client mistakes.

    A 200 here is the worst outcome: the caller believes the field was applied.
    The same shape makes a typo'd security-relevant field a silent no-op --
    `{"stok_qty": 0}` reports success and changes nothing.
    """
    response = client.patch(
        f"/products/{seeded['widget_id']}",
        json={"stok_qty": 0, "not_a_field": "ignored"},
    )

    assert response.status_code == 200
    assert response.json()["stock_qty"] == 10
