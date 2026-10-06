"""HTTP routes for products and orders.

!!! DELIBERATELY VULNERABLE -- PLAN.md step 2, "break" phase !!!

No authentication or authorization yet; those are steps 4-6. The two flaws
this version exists to demonstrate:

1. **Mass assignment.** Every write handler spreads the client's parsed body
   straight into the ORM object (`**payload.model_dump()`). Whatever the client
   sent, the database gets -- including `id`, `status` and `total_cents`.
2. **SQL injection.** `GET /products/search` interpolates `q` into a `text()`
   query, so the query string is SQL. Note that the endpoint's response model
   does not constrain the *shape* of what comes back: a `UNION` returning five
   columns of anything at all will be happily serialised as products.

Both are fixed in the second half of step 2.
"""

from collections.abc import Iterator
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select, text
from sqlalchemy.orm import Session, sessionmaker

from rlapi.models import Order, OrderItem, Product
from rlapi.schemas import OrderPayload, ProductPayload


def get_session(request: Request) -> Iterator[Session]:
    """Per-request session, committed on success and rolled back on error.

    The factory is held on `app.state` rather than imported as a module global
    so that tests can inject an in-memory database. Step 1's hardening travels
    with the engine, so whatever is injected here is hardened too -- except in
    the attack suite, which builds a raw engine on purpose.
    """
    factory: sessionmaker[Session] = request.app.state.session_factory
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


SessionDep = Annotated[Session, Depends(get_session)]

products = APIRouter(prefix="/products", tags=["products"])
orders = APIRouter(prefix="/orders", tags=["orders"])


# ---------------------------------------------------------------------------
# Products
# ---------------------------------------------------------------------------
@products.post("", response_model=ProductPayload, status_code=status.HTTP_201_CREATED)
def create_product(payload: ProductPayload, session: SessionDep) -> Product:
    product = Product(**payload.model_dump(exclude_unset=True))
    session.add(product)
    session.flush()
    return product


@products.get("", response_model=list[ProductPayload])
def list_products(session: SessionDep) -> list[Product]:
    return list(session.scalars(select(Product).order_by(Product.id)))


@products.get("/search", response_model=list[ProductPayload])
def search_products(
    session: SessionDep, q: Annotated[str, Query()] = ""
) -> list[dict[str, object]]:
    """Substring search over product names.

    The f-string is the vulnerability. `q` arrives as a query-string value and
    is spliced into SQL, so a caller controls the statement rather than one of
    its values.

    Ruff *does* flag this one (`S608`), which is why the suppression below has
    to be explicit. Measured at step 2: it would **not** have flagged the same
    bug written as `f"{base} WHERE name LIKE '%{q}%'"` with the `SELECT` in a
    variable one line up. See THREAT_MODEL.md F-08.
    """
    sql = f"SELECT * FROM products WHERE name LIKE '%{q}%'"  # noqa: S608  -- intentional, see PLAN.md step 2
    rows = session.execute(text(sql)).mappings().all()
    return [dict(row) for row in rows]


@products.get("/{product_id}", response_model=ProductPayload)
def get_product(product_id: int, session: SessionDep) -> Product:
    return _require(session.get(Product, product_id), "product")


@products.patch("/{product_id}", response_model=ProductPayload)
def update_product(product_id: int, payload: ProductPayload, session: SessionDep) -> Product:
    product = _require(session.get(Product, product_id), "product")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(product, field, value)
    session.flush()
    return product


@products.delete("/{product_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_product(product_id: int, session: SessionDep) -> None:
    session.delete(_require(session.get(Product, product_id), "product"))


# ---------------------------------------------------------------------------
# Orders
# ---------------------------------------------------------------------------
@orders.post("", response_model=OrderPayload, status_code=status.HTTP_201_CREATED)
def create_order(payload: OrderPayload, session: SessionDep) -> Order:
    order = Order(**payload.model_dump(exclude_unset=True, exclude={"items"}))
    for item in payload.items or []:
        order.items.append(OrderItem(**item.model_dump(exclude_unset=True)))
    session.add(order)
    session.flush()
    return order


@orders.get("", response_model=list[OrderPayload])
def list_orders(session: SessionDep) -> list[Order]:
    return list(session.scalars(select(Order).order_by(Order.id)))


@orders.get("/{order_id}", response_model=OrderPayload)
def get_order(order_id: int, session: SessionDep) -> Order:
    return _require(session.get(Order, order_id), "order")


@orders.patch("/{order_id}", response_model=OrderPayload)
def update_order(order_id: int, payload: OrderPayload, session: SessionDep) -> Order:
    order = _require(session.get(Order, order_id), "order")
    for field, value in payload.model_dump(exclude_unset=True, exclude={"items"}).items():
        setattr(order, field, value)
    session.flush()
    return order


@orders.delete("/{order_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_order(order_id: int, session: SessionDep) -> None:
    session.delete(_require(session.get(Order, order_id), "order"))


def _require[T](obj: T | None, what: str) -> T:
    """404 on a missing row.

    Deliberately says only "product not found", with no indication of whether
    the id exists but belongs to someone else. Step 5 adds ownership checks,
    and that is the point at which a distinguishable 403-vs-404 becomes an
    enumeration oracle.
    """
    if obj is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"{what} not found")
    return obj
