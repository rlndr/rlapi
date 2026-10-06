"""HTTP routes for products and orders.

Step 2's fix. No authentication or authorization yet -- those are steps 4-6,
and until then any caller can act as any customer. That gap is deliberate and
tracked, not overlooked.

What changed from the break phase:

- **Input models are the allowlist.** Handlers still spread
  `payload.model_dump(exclude_unset=True)`, and that is now safe *because of
  the model*, not because of a check here: `ProductUpdate` has exactly four
  fields and `extra="forbid"`, so there is nothing else to spread. Worth being
  clear that the fix lives in `schemas.py`; this module merely stopped being
  handed a model that could carry anything.
- **Server-derived values are computed here.** `total_cents` is summed from the
  line items, `unit_price_cents` is read from the product, and a new order is
  always `draft`.
- **Status moves through `ALLOWED_TRANSITIONS`.** There is no writable `status`
  field anywhere; `PATCH /orders/{id}` no longer exists.
- **No raw SQL.** The search is an ORM `select()`. Parameterising the old
  `text()` query would have been enough to stop the injection, but removing the
  string-building removes the shape of the bug -- and `.contains(autoescape=True)`
  also closes the wildcard hole that bound parameters leave wide open (a bound
  `%` is still a LIKE wildcard).
"""

from collections.abc import Iterator
from typing import Annotated, Final

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload, sessionmaker

from rlapi.models import Order, OrderItem, OrderStatus, Product
from rlapi.schemas import (
    OrderCreate,
    OrderRead,
    OrderStatusChange,
    ProductCreate,
    ProductRead,
    ProductUpdate,
)

#: The order workflow, stated once. An order may always be cancelled until it
#: has shipped; `shipped` and `cancelled` are terminal.
#:
#: This table is the reason `status` is not a writable field. A PATCH field can
#: express "status is a string from this enum"; it cannot express "draft may
#: become placed but not shipped", which is the property that stops the break
#: phase's draft-to-shipped jump.
ALLOWED_TRANSITIONS: Final[dict[OrderStatus, frozenset[OrderStatus]]] = {
    OrderStatus.DRAFT: frozenset({OrderStatus.PLACED, OrderStatus.CANCELLED}),
    OrderStatus.PLACED: frozenset({OrderStatus.PAID, OrderStatus.CANCELLED}),
    OrderStatus.PAID: frozenset({OrderStatus.SHIPPED, OrderStatus.CANCELLED}),
    OrderStatus.SHIPPED: frozenset(),
    OrderStatus.CANCELLED: frozenset(),
}

#: Caps the page size so a single request cannot ask for the whole table.
MAX_PAGE_SIZE: Final = 100

#: Bounds the search term. Not a security control on its own -- the ORM query
#: is -- but an unbounded query string is free work for anyone who asks.
SEARCH_MAX_LEN: Final = 200


def get_session(request: Request) -> Iterator[Session]:
    """Per-request session, committed on success and rolled back on error.

    The factory is held on `app.state` rather than imported as a module global
    so that tests can inject their own database. Step 1's hardening travels
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
LimitDep = Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)]
OffsetDep = Annotated[int, Query(ge=0)]

products = APIRouter(prefix="/products", tags=["products"])
orders = APIRouter(prefix="/orders", tags=["orders"])


# ---------------------------------------------------------------------------
# Products
# ---------------------------------------------------------------------------
@products.post("", response_model=ProductRead, status_code=status.HTTP_201_CREATED)
def create_product(payload: ProductCreate, session: SessionDep) -> Product:
    product = Product(**payload.model_dump())
    session.add(product)
    session.flush()
    return product


@products.get("", response_model=list[ProductRead])
def list_products(
    session: SessionDep, limit: LimitDep = 50, offset: OffsetDep = 0
) -> list[Product]:
    stmt = select(Product).order_by(Product.id).limit(limit).offset(offset)
    return list(session.scalars(stmt))


@products.get("/search", response_model=list[ProductRead])
def search_products(
    session: SessionDep,
    q: Annotated[str, Query(max_length=SEARCH_MAX_LEN)] = "",
    limit: LimitDep = 50,
) -> list[Product]:
    """Substring search over product names.

    `autoescape=True` is doing work that is easy to miss. Bound parameters stop
    the injection, but `%` and `_` are LIKE metacharacters *inside* a bound
    value -- so a parameterised query with `q="%"` still returns the entire
    catalogue. Escaping makes the search mean what it says.
    """
    stmt = (
        select(Product)
        .where(Product.name.contains(q, autoescape=True))
        .order_by(Product.id)
        .limit(limit)
    )
    return list(session.scalars(stmt))


@products.get("/{product_id}", response_model=ProductRead)
def get_product(product_id: int, session: SessionDep) -> Product:
    return _require(session.get(Product, product_id), "product")


@products.patch("/{product_id}", response_model=ProductRead)
def update_product(product_id: int, payload: ProductUpdate, session: SessionDep) -> Product:
    product = _require(session.get(Product, product_id), "product")
    # Safe because `ProductUpdate` is the allowlist: four fields, no `id`, and
    # `extra="forbid"` means an unknown key never reaches this loop.
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
@orders.post("", response_model=OrderRead, status_code=status.HTTP_201_CREATED)
def create_order(payload: OrderCreate, session: SessionDep) -> Order:
    """Create a draft order, priced by the server.

    Every money value here is derived: the unit price comes from the product
    row, and the total is the sum of the lines. Nothing about the price comes
    from the request.
    """
    order = Order(customer_id=payload.customer_id, status=OrderStatus.DRAFT, total_cents=0)

    total = 0
    for line in payload.items:
        product = session.get(Product, line.product_id)
        if product is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"product {line.product_id} does not exist",
            )
        order.items.append(
            OrderItem(
                product_id=product.id,
                qty=line.qty,
                unit_price_cents=product.price_cents,
            )
        )
        total += product.price_cents * line.qty

    order.total_cents = total
    session.add(order)
    session.flush()
    return order


@orders.get("", response_model=list[OrderRead])
def list_orders(session: SessionDep, limit: LimitDep = 50, offset: OffsetDep = 0) -> list[Order]:
    stmt = (
        select(Order)
        .options(selectinload(Order.items))
        .order_by(Order.id)
        .limit(limit)
        .offset(offset)
    )
    return list(session.scalars(stmt))


@orders.get("/{order_id}", response_model=OrderRead)
def get_order(order_id: int, session: SessionDep) -> Order:
    return _require(session.get(Order, order_id), "order")


@orders.post("/{order_id}/status", response_model=OrderRead)
def change_order_status(order_id: int, payload: OrderStatusChange, session: SessionDep) -> Order:
    """Move an order along the workflow, or refuse.

    409 rather than 422: the request is well-formed, it conflicts with the
    order's current state. The message names both states because this is not
    sensitive information -- the caller already knows the order.
    """
    order = _require(session.get(Order, order_id), "order")
    if payload.to not in ALLOWED_TRANSITIONS[order.status]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"cannot move order from {order.status.value} to {payload.to.value}",
        )
    order.status = payload.to
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
