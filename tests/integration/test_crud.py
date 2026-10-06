"""The endpoints doing their actual job.

The attack suite proves what the API refuses. These prove it still works --
which is the half that catches a "fix" that simply rejects everything. A
validation control is only correct if the legitimate request still passes.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from rlapi.models import Product
from rlapi.routes import MAX_PAGE_SIZE


def test_healthz(client: TestClient) -> None:
    assert client.get("/healthz").json() == {"status": "ok"}


def test_product_lifecycle(client: TestClient) -> None:
    created = client.post(
        "/products",
        json={"sku": "SKU-NEW", "name": "New Thing", "price_cents": 250, "stock_qty": 7},
    )
    assert created.status_code == 201
    product = created.json()
    assert product["sku"] == "SKU-NEW"
    product_id = product["id"]

    fetched = client.get(f"/products/{product_id}")
    assert fetched.status_code == 200
    assert fetched.json() == product

    patched = client.patch(f"/products/{product_id}", json={"price_cents": 300})
    assert patched.status_code == 200
    assert patched.json()["price_cents"] == 300
    assert patched.json()["stock_qty"] == 7, "PATCH must not reset untouched fields"

    assert client.delete(f"/products/{product_id}").status_code == 204
    assert client.get(f"/products/{product_id}").status_code == 404


def test_product_defaults_are_applied(client: TestClient) -> None:
    """`price_cents` and `stock_qty` are optional on create."""
    created = client.post("/products", json={"sku": "SKU-BARE", "name": "Bare"})
    assert created.status_code == 201
    assert created.json()["price_cents"] == 0
    assert created.json()["stock_qty"] == 0


@pytest.mark.usefixtures("seeded")
def test_duplicate_sku_is_rejected(client: TestClient) -> None:
    """The unique index is the control; it surfaces as an unhandled 500.

    Pinned as it actually behaves rather than as it should: there is no
    integrity-error handler yet, so a duplicate SKU is a 500 rather than a 409.
    Recorded in PLAN.md section 0's open items rather than silently tolerated.
    """
    with pytest.raises(IntegrityError, match="UNIQUE constraint failed"):
        client.post("/products", json={"sku": "SKU-WIDGET", "name": "Collision"})


def test_order_is_priced_and_statused_by_the_server(
    client: TestClient, seeded: dict[str, int]
) -> None:
    response = client.post(
        "/orders",
        json={
            "customer_id": seeded["customer_id"],
            "items": [
                {"product_id": seeded["widget_id"], "qty": 2},
                {"product_id": seeded["gadget_id"], "qty": 1},
            ],
        },
    )

    assert response.status_code == 201
    order = response.json()
    assert order["status"] == "draft"
    # 1999 x 2 + 4950 x 1
    assert order["total_cents"] == 8948
    assert {item["unit_price_cents"] for item in order["items"]} == {1999, 4950}


def test_order_total_is_unaffected_by_a_later_price_change(
    client: TestClient, seeded: dict[str, int]
) -> None:
    """Why `unit_price_cents` is denormalised, asserted rather than assumed."""
    created = client.post(
        "/orders",
        json={
            "customer_id": seeded["customer_id"],
            "items": [{"product_id": seeded["widget_id"], "qty": 1}],
        },
    )
    order_id = created.json()["id"]
    assert created.json()["total_cents"] == 1999

    assert client.patch(f"/products/{seeded['widget_id']}", json={"price_cents": 99999}).is_success

    refetched = client.get(f"/orders/{order_id}")
    assert refetched.json()["total_cents"] == 1999
    assert refetched.json()["items"][0]["unit_price_cents"] == 1999


def test_order_referencing_a_missing_product_is_refused(
    client: TestClient, seeded: dict[str, int]
) -> None:
    response = client.post(
        "/orders",
        json={"customer_id": seeded["customer_id"], "items": [{"product_id": 99999, "qty": 1}]},
    )

    assert response.status_code == 422
    assert "99999" in response.json()["detail"]


def test_order_can_be_cancelled_from_any_pre_shipped_state(
    client: TestClient, seeded: dict[str, int]
) -> None:
    order_id = seeded["order_id"]
    assert client.post(f"/orders/{order_id}/status", json={"to": "placed"}).is_success
    cancelled = client.post(f"/orders/{order_id}/status", json={"to": "cancelled"})
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelled"


def test_unknown_status_value_is_rejected(client: TestClient, seeded: dict[str, int]) -> None:
    """The enum is the control here, not the transition table."""
    response = client.post(f"/orders/{seeded['order_id']}/status", json={"to": "refunded"})
    assert response.status_code == 422


@pytest.mark.usefixtures("seeded")
def test_search_matches_a_substring(client: TestClient) -> None:
    results = client.get("/products/search", params={"q": "dge"}).json()
    assert {row["sku"] for row in results} == {"SKU-WIDGET", "SKU-GADGET"}


@pytest.mark.usefixtures("seeded")
def test_empty_search_returns_the_catalogue(client: TestClient) -> None:
    assert len(client.get("/products/search").json()) == 2


def test_pagination_bounds_are_enforced(
    client: TestClient, session_factory: sessionmaker[Session]
) -> None:
    with session_factory.begin() as session:
        session.add_all(
            Product(sku=f"SKU-{n:03d}", name=f"Item {n}", price_cents=n, stock_qty=1)
            for n in range(10)
        )

    assert len(client.get("/products", params={"limit": 3}).json()) == 3
    assert len(client.get("/products", params={"limit": 3, "offset": 9}).json()) == 1

    assert client.get("/products", params={"limit": MAX_PAGE_SIZE + 1}).status_code == 422
    assert client.get("/products", params={"limit": 0}).status_code == 422
    assert client.get("/products", params={"offset": -1}).status_code == 422


def test_openapi_schema_is_served(client: TestClient) -> None:
    """Cheap smoke test with real value: it fails if any response model is
    unserialisable, which is otherwise only noticed at request time."""
    schema = client.get("/openapi.json")
    assert schema.status_code == 200
    assert "ProductCreate" in schema.json()["components"]["schemas"]
