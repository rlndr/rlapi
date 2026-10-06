"""Mass assignment: the client writes fields the server owns.

PLAN.md step:      2
OWASP:             MCP05 per the plan; MCP07 is the sharper fit (see below)
Vulnerable commit: 3a062b5
Findings:          THREAT_MODEL.md F-09, F-10, F-13

Every test here ran green against the vulnerable code first. The payloads are
unchanged from the break phase -- only the expected outcome moved -- which is
what makes these regression tests rather than tests that merely pass.

What was observed before the fix, so the "what did this actually prevent?"
question has an answer later:

- `PATCH /products/{id}` with `{"id": 9999}` moved the row's primary key.
- `POST /orders` with `status="shipped", total_cents=0` created a shipped,
  free order, and `unit_price_cents=1` bought a 4950c product for 1c.
- `PATCH /orders/{id}` jumped draft straight to shipped.
- `{"stok_qty": 0}` returned 200 and changed nothing.

The control is `schemas.py`: direction-specific models where the dangerous
fields are *absent*, plus `extra="forbid"`. Not a check in the handler.

Marked `mcp05` to match PLAN.md's category for step 2, though the sharper fit
is MCP07: the API has no notion of which fields a caller may write. Step 5
makes that explicit per role.
"""

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from rlapi.models import Order, OrderStatus, Product

pytestmark = [pytest.mark.attack, pytest.mark.mcp05]

UNPROCESSABLE = 422


def _rejected_fields(response: httpx.Response) -> set[str]:
    """The field names FastAPI's 422 body blames, for asserting *why* it failed.

    A 422 that happens for the wrong reason is a passing test that proves
    nothing, which is the usual way an inverted exploit test rots.
    """
    return {str(error["loc"][-1]) for error in response.json()["detail"]}


def test_product_id_is_not_an_accepted_input_field(
    client: TestClient, seeded: dict[str, int], session_factory: sessionmaker[Session]
) -> None:
    """Previously moved the row to id 9999. Now a 422 naming `id`.

    The two assertions below are held by *different* controls, which is worth
    stating because it would be easy to credit the wrong one. Measured by
    removing `extra="forbid"` and re-running this request:

    - The row does not move because `id` is **absent from `ProductUpdate`**.
      With `extra="ignore"` the field is dropped before the handler sees it, so
      the PATCH returns 200, applies the other fields, and the primary key
      stays put. Field absence is the control that prevents the write.
    - The 422 comes from `extra="forbid"` alone. Without it the request is a
      silent success. That control prevents the *silence*, not the write.

    Both matter. A caller who believes it reassigned an id and was told 200 is
    a different failure from one that actually did.
    """
    original = seeded["gadget_id"]

    response = client.patch(f"/products/{original}", json={"id": 9999})

    assert response.status_code == UNPROCESSABLE
    assert "id" in _rejected_fields(response)

    with session_factory() as session:
        assert session.get(Product, original) is not None
        assert session.get(Product, 9999) is None


def test_input_schemas_do_not_expose_server_owned_fields(client: TestClient) -> None:
    """Pin the primary control directly: the fields simply are not there.

    Asserted against the OpenAPI document rather than by sending requests,
    because this is a property of the schema, not of any one payload. If
    someone later adds `status` back to `OrderCreate`, this fails immediately
    even if no exploit test happens to cover that field.
    """
    schemas = client.get("/openapi.json").json()["components"]["schemas"]

    forbidden = {
        "ProductCreate": {"id"},
        "ProductUpdate": {"id"},
        "OrderCreate": {"id", "status", "total_cents"},
        "OrderItemCreate": {"id", "order_id", "unit_price_cents"},
    }
    for model, banned in forbidden.items():
        present = set(schemas[model]["properties"])
        assert not (present & banned), f"{model} exposes server-owned field(s): {present & banned}"
        # `additionalProperties: false` is how `extra="forbid"` is published.
        assert schemas[model]["additionalProperties"] is False, f"{model} is not strict"


def test_referenced_product_is_now_protected_by_the_schema_not_the_database(
    client: TestClient, seeded: dict[str, int]
) -> None:
    """The incidental control from F-09 is no longer what stops this.

    Before the fix, a referenced product survived PK reassignment only because
    SQLite raised `FOREIGN KEY constraint failed` -- an unhandled 500, and only
    for rows that happened to have order history. Now both referenced and
    unreferenced products are refused identically at the edge, with a 422.

    Asserting the *same* status for both cases is the point: the outcome no
    longer depends on whether a product has been ordered.
    """
    referenced = client.patch(f"/products/{seeded['widget_id']}", json={"id": 9999})
    unreferenced = client.patch(f"/products/{seeded['gadget_id']}", json={"id": 9998})

    assert referenced.status_code == unreferenced.status_code == UNPROCESSABLE


def test_order_status_and_total_are_not_accepted_on_create(
    client: TestClient, seeded: dict[str, int]
) -> None:
    """The one that mattered: previously created a shipped, free order."""
    response = client.post(
        "/orders",
        json={
            "customer_id": seeded["customer_id"],
            "status": "shipped",
            "total_cents": 0,
            "items": [{"product_id": seeded["gadget_id"], "qty": 1}],
        },
    )

    assert response.status_code == UNPROCESSABLE
    assert {"status", "total_cents"} <= _rejected_fields(response)


def test_unit_price_is_not_accepted_and_is_read_from_the_product(
    client: TestClient, seeded: dict[str, int]
) -> None:
    """Rejected outright, and the price the server uses is the catalogue's."""
    attempt = client.post(
        "/orders",
        json={
            "customer_id": seeded["customer_id"],
            "items": [{"product_id": seeded["gadget_id"], "qty": 2, "unit_price_cents": 1}],
        },
    )
    assert attempt.status_code == UNPROCESSABLE
    assert "unit_price_cents" in _rejected_fields(attempt)

    # The same order without the injected price is priced from the product:
    # 4950c x 2. Asserting the derived value, not just the rejection, is what
    # shows the server is the source of the number.
    honest = client.post(
        "/orders",
        json={
            "customer_id": seeded["customer_id"],
            "items": [{"product_id": seeded["gadget_id"], "qty": 2}],
        },
    )
    assert honest.status_code == 201
    body = honest.json()
    assert body["items"][0]["unit_price_cents"] == 4950
    assert body["total_cents"] == 9900
    assert body["status"] == OrderStatus.DRAFT.value


def test_there_is_no_patch_route_for_orders(
    client: TestClient, seeded: dict[str, int], session_factory: sessionmaker[Session]
) -> None:
    """Zeroing a total needed a writable field; the route itself is gone.

    405 rather than 422: removing the capability is a stronger fix than
    validating it, because there is no field list to keep in sync.
    """
    response = client.patch(f"/orders/{seeded['order_id']}", json={"total_cents": 0})

    assert response.status_code == 405
    with session_factory() as session:
        order = session.get(Order, seeded["order_id"])
        assert order is not None
        assert order.total_cents == 1999


def test_status_cannot_skip_the_workflow(client: TestClient, seeded: dict[str, int]) -> None:
    """draft -> shipped is refused; draft -> placed is allowed.

    Both halves matter. A transition table that refuses everything would pass
    the first assertion and be useless.
    """
    jump = client.post(f"/orders/{seeded['order_id']}/status", json={"to": "shipped"})
    assert jump.status_code == 409
    assert "draft" in jump.json()["detail"]

    legal = client.post(f"/orders/{seeded['order_id']}/status", json={"to": "placed"})
    assert legal.status_code == 200
    assert legal.json()["status"] == OrderStatus.PLACED.value


def test_terminal_status_cannot_be_moved(client: TestClient, seeded: dict[str, int]) -> None:
    """Walk to `shipped` legally, then confirm it is a dead end."""
    order_id = seeded["order_id"]
    for target in ("placed", "paid", "shipped"):
        step = client.post(f"/orders/{order_id}/status", json={"to": target})
        assert step.status_code == 200, f"legal transition to {target} was refused"

    assert client.post(f"/orders/{order_id}/status", json={"to": "cancelled"}).status_code == 409
    assert client.post(f"/orders/{order_id}/status", json={"to": "draft"}).status_code == 409


def test_unknown_fields_are_rejected_rather_than_ignored(
    client: TestClient, seeded: dict[str, int]
) -> None:
    """`extra="forbid"`. Previously a 200 that silently changed nothing.

    The typo is the realistic case: a caller sending `stok_qty` believed it had
    set the stock to zero, and the API agreed.
    """
    response = client.patch(
        f"/products/{seeded['widget_id']}",
        json={"stok_qty": 0, "not_a_field": "ignored"},
    )

    assert response.status_code == UNPROCESSABLE
    assert {"stok_qty", "not_a_field"} <= _rejected_fields(response)


def test_field_constraints_are_enforced_before_the_check_constraints(
    client: TestClient, seeded: dict[str, int]
) -> None:
    """The API refuses negative money with a 422, not a 500.

    `models.py` has CHECK constraints for these, and step 11 revisits negative
    quantities properly. The distinction being pinned here is which layer
    answers: a 422 from Pydantic means the control held, while a 500 from
    SQLite would mean the backstop caught what the control missed.
    """
    negative_price = client.patch(f"/products/{seeded['widget_id']}", json={"price_cents": -1})
    assert negative_price.status_code == UNPROCESSABLE

    zero_qty = client.post(
        "/orders",
        json={
            "customer_id": seeded["customer_id"],
            "items": [{"product_id": seeded["widget_id"], "qty": 0}],
        },
    )
    assert zero_qty.status_code == UNPROCESSABLE

    empty_order = client.post("/orders", json={"customer_id": seeded["customer_id"], "items": []})
    assert empty_order.status_code == UNPROCESSABLE
