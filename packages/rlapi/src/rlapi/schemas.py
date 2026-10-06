"""Request/response models.

!!! DELIBERATELY VULNERABLE -- PLAN.md step 2, "break" phase !!!

This is the lazy shape, written on purpose so the exploit can be observed
before it is fixed:

- **One model per entity, used in both directions.** `ProductPayload` is the
  request body for create *and* update, and the response model as well. Every
  field is therefore optional (an update sends a subset) and writable (a
  response must be able to carry them all).
- **No `extra="forbid"`.** Pydantic v2 defaults to `extra="ignore"`, so a
  misspelled field is accepted with a 200 and silently does nothing.
- **Server-derived fields are in the input model.** `Order.total_cents` and
  `Order.status` are the API's job to compute, but here a client can set them.

The fix in the second half of step 2 splits these into `*Create`, `*Update` and
`*Read` models. Keeping the vulnerable version in its own commit is the point:
`tests/attacks/test_mass_assignment.py` is written against *this* code and
proves the exploit lands, so that when it later fails it is failing for a
reason that was actually demonstrated.
"""

from pydantic import BaseModel

from rlapi.models import OrderStatus


class ProductPayload(BaseModel):
    """Create, update, and read -- all three. Hence everything optional."""

    id: int | None = None
    sku: str | None = None
    name: str | None = None
    price_cents: int | None = None
    stock_qty: int | None = None


class OrderItemPayload(BaseModel):
    id: int | None = None
    order_id: int | None = None
    product_id: int | None = None
    qty: int | None = None
    # Denormalised price-at-time-of-order. The server must read this from the
    # product; accepting it from the client is how an order gets a unit price
    # the catalogue never offered.
    unit_price_cents: int | None = None


class OrderPayload(BaseModel):
    id: int | None = None
    customer_id: int | None = None
    # Both server-derived. `status` is a workflow state the API owns, and
    # `total_cents` must equal the sum of the line items or the order is a lie.
    status: OrderStatus | None = None
    total_cents: int | None = None
    items: list[OrderItemPayload] | None = None
