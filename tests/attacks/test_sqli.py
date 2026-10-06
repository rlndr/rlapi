"""SQL injection in the product search.

PLAN.md step:      2
OWASP:             MCP05
Vulnerable commit: 3a062b5
Findings:          THREAT_MODEL.md F-08, F-11, F-12

Every payload here ran green against the vulnerable code first, where
`GET /products/search` built its query as
`f"SELECT * FROM products WHERE name LIKE '%{q}%'"`. What was observed then:

- `' UNION SELECT id, email, role, 0, 0 FROM users --` returned every user's
  email and role, serialised as products.
- `' OR 1=1 --` returned the whole catalogue.
- A bare `'` raised an unhandled `OperationalError` whose message embedded the
  failed statement -- an oracle for reconstructing the query shape.
- `sqlite_master` was readable, giving every table name and its DDL.

The control is that there is no SQL string any more: the endpoint is an ORM
`select()` with `.contains(autoescape=True)`. Ruff `S608` no longer has
anything to flag, which is the weaker half of the evidence -- see
THREAT_MODEL.md F-08 for the shape of this same bug that S608 never flagged at
all.
"""

import pytest
from fastapi.testclient import TestClient

# `seeded` is required for its side effect only -- these tests assert on what
# the injection reaches, not on the seeded ids.
pytestmark = [pytest.mark.attack, pytest.mark.mcp05, pytest.mark.usefixtures("seeded")]

#: Five columns to match `SELECT *` on products (id, sku, name, price_cents,
#: stock_qty). The trailing `--` commented out the rest of the LIKE pattern.
UNION_EXFIL = "' UNION SELECT id, email, role, 0, 0 FROM users --"

SQLITE_MASTER_EXFIL = "' UNION SELECT 0, name, sql, 0, 0 FROM sqlite_master WHERE type='table' --"


def test_union_select_is_treated_as_a_product_name(client: TestClient) -> None:
    """The payload from PLAN.md step 2, verbatim. Now it is just a string.

    Asserting an empty result rather than "no email in the response": the query
    searches for a product literally named `' UNION SELECT ...`, finds none,
    and returns nothing. A test that only checked for absent emails would also
    pass if the endpoint were broken.
    """
    response = client.get("/products/search", params={"q": UNION_EXFIL})

    assert response.status_code == 200
    assert response.json() == []


def test_injection_cannot_reach_the_users_table(client: TestClient) -> None:
    """Belt and braces: no row from any payload may carry user data.

    The vulnerable version leaked emails through `sku` and roles through `name`,
    because UNION result columns are named by the first select. Checking the
    serialised body for an `@` catches that shape regardless of which field it
    arrives in.
    """
    for payload in (UNION_EXFIL, SQLITE_MASTER_EXFIL, "' OR 1=1 --", "%' UNION SELECT 1 --"):
        body = client.get("/products/search", params={"q": payload}).text
        assert "@example.test" not in body, f"user data leaked via {payload!r}"
        assert "admin" not in body, f"role leaked via {payload!r}"


def test_tautology_does_not_widen_the_result_set(client: TestClient) -> None:
    """`' OR 1=1 --` returned both products before; now it matches none."""
    narrow = client.get("/products/search", params={"q": "Widget"})
    assert len(narrow.json()) == 1

    tautology = client.get("/products/search", params={"q": "' OR 1=1 --"})
    assert tautology.json() == []


def test_a_bare_quote_is_an_ordinary_search_term(client: TestClient) -> None:
    """The error oracle is gone: 200 with no matches, not an unhandled 500.

    Previously this raised `OperationalError`, and SQLAlchemy's message
    embedded the malformed statement, which told an attacker the column count
    for the UNION rather than making them guess it.
    """
    response = client.get("/products/search", params={"q": "'"})

    assert response.status_code == 200
    assert response.json() == []


def test_sqlite_master_is_not_readable_through_the_search(client: TestClient) -> None:
    """Reconnaissance is closed. Previously returned every table name and DDL."""
    response = client.get("/products/search", params={"q": SQLITE_MASTER_EXFIL})

    assert response.status_code == 200
    assert response.json() == []


def test_like_wildcards_in_the_search_term_are_escaped(client: TestClient) -> None:
    """The hole that bound parameters alone would have left open.

    Parameterising the old `text()` query stops injection, but `%` and `_` are
    LIKE metacharacters *inside* a bound value -- so `q="%"` would still return
    the entire catalogue, and `q="W_dget"` would still match "Widget". That is
    not SQL injection, but it is the filter being switched off by input, which
    is the same failure the tautology test covers. `autoescape=True` is what
    closes it.
    """
    everything = client.get("/products/search", params={"q": "%"})
    assert everything.json() == [], "`%` still behaving as a wildcard"

    single_char = client.get("/products/search", params={"q": "W_dget"})
    assert single_char.json() == [], "`_` still behaving as a wildcard"

    # The escaping must not break ordinary matching.
    assert len(client.get("/products/search", params={"q": "idge"}).json()) == 1


def test_the_search_endpoint_no_longer_builds_sql_strings() -> None:
    """Assert the absence of the bug's shape, not just of its effect.

    The exploit tests above would all pass against a parameterised `text()`
    query too. This one pins the stronger property: no raw SQL and no
    suppressed `S608` remain in the module, so the next person to touch the
    endpoint has to reintroduce both to reintroduce the vulnerability.

    Done over the AST and the token stream rather than by substring search.
    A first attempt grepped the source text and failed on the module's own
    docstring, which discusses `text()` -- a test that reads prose cannot tell
    a warning about a vulnerability from the vulnerability.
    """
    import ast
    import io
    import tokenize
    from pathlib import Path

    import rlapi.routes

    source = Path(rlapi.routes.__file__).read_text()
    tree = ast.parse(source)

    called = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "text" not in called, "raw SQL construction is back in the search endpoint"

    comments = [
        token.string
        for token in tokenize.generate_tokens(io.StringIO(source).readline)
        if token.type == tokenize.COMMENT
    ]
    assert not [c for c in comments if "S608" in c], "an S608 suppression is back"
