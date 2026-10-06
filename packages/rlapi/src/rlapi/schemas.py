"""Request/response models.

Step 2's fix. Three rules, each of which exists because the break phase showed
what happens without it:

1. **One model per direction.** `ProductCreate`, `ProductUpdate`, `ProductRead`.
   A field is writable only where writing it is meaningful, so `id` is simply
   absent from both input models and the mass-assignment path has nothing to
   assign to. This is the control: not a check that rejects `id`, but a schema
   in which `id` does not exist as an input.
2. **`extra="forbid"` everywhere on input.** Pydantic defaults to
   `extra="ignore"`, which turns a misspelled field into a silent no-op with a
   200. A 422 is the only honest answer to a field the server does not
   recognise. `STRICT_INPUT` is applied to every input model so a new one
   cannot be added without it.
3. **Server-derived fields are not in any input model.** `total_cents`,
   `status` and `unit_price_cents` are computed or looked up in `routes.py`.
   Accepting `unit_price_cents` let a client buy at a price the catalogue never
   offered; accepting `total_cents` and `status` let one ship goods for free.

Constraints are duplicated from `models.py` on purpose -- `qty > 0` is both a
Pydantic `gt=0` and a CHECK constraint. The schema is the control, giving a 422
at the edge; the CHECK is the backstop for when the control has a bug, giving a
500 instead of corrupt data. Neither makes the other redundant.
"""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from rlapi.models import EMAIL_MAX_LEN, NAME_MAX_LEN, SKU_MAX_LEN, OrderStatus

#: Applied to every model that parses client input. Rejecting unknown fields is
#: the half of input validation that is easy to forget, because omitting it
#: produces no error anywhere -- just writes that silently do not happen.
STRICT_INPUT = ConfigDict(extra="forbid")

#: Reused so the two directions cannot drift apart.
Sku = Annotated[str, Field(min_length=1, max_length=SKU_MAX_LEN)]
ProductName = Annotated[str, Field(min_length=1, max_length=NAME_MAX_LEN)]
PriceCents = Annotated[int, Field(ge=0)]
StockQty = Annotated[int, Field(ge=0)]
Quantity = Annotated[int, Field(gt=0)]


# ---------------------------------------------------------------------------
# Products
# ---------------------------------------------------------------------------
class ProductCreate(BaseModel):
    model_config = STRICT_INPUT

    sku: Sku
    name: ProductName
    price_cents: PriceCents = 0
    stock_qty: StockQty = 0


class ProductUpdate(BaseModel):
    """PATCH: every field optional, but `id` is not among them.

    `model_fields_set` distinguishes "absent" from "explicitly null", which is
    why the handler uses `exclude_unset` rather than dropping `None`s.
    """

    model_config = STRICT_INPUT

    sku: Sku | None = None
    name: ProductName | None = None
    price_cents: PriceCents | None = None
    stock_qty: StockQty | None = None


class ProductRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    sku: str
    name: str
    price_cents: int
    stock_qty: int


# ---------------------------------------------------------------------------
# Orders
# ---------------------------------------------------------------------------
class OrderItemCreate(BaseModel):
    """What a client may say about a line item: which product, how many.

    `unit_price_cents` is deliberately absent. The server reads it from the
    product at the moment the order is created, which is both the security
    property and the reason the column is denormalised in the first place.
    """

    model_config = STRICT_INPUT

    product_id: int = Field(gt=0)
    qty: Quantity


class OrderCreate(BaseModel):
    """No `status`, no `total_cents`, no `id`. Those are the server's.

    `customer_id` is still accepted here because there is no authentication
    yet. It becomes the token's `sub` at step 5 -- until then, any caller can
    place an order as anyone, which is step 5's IDOR and is tracked as such
    rather than pretended away.
    """

    model_config = STRICT_INPUT

    customer_id: int = Field(gt=0)
    items: list[OrderItemCreate] = Field(min_length=1)


class OrderStatusChange(BaseModel):
    """The only way to move an order's status.

    A dedicated endpoint rather than a PATCH field, so that every transition
    goes through the explicit table in `routes.py`. A writable `status` field
    cannot express "draft may become placed but not shipped".
    """

    model_config = STRICT_INPUT

    to: OrderStatus


class OrderItemRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    product_id: int
    qty: int
    unit_price_cents: int


class OrderRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    customer_id: int
    status: OrderStatus
    total_cents: int
    items: list[OrderItemRead]


class UserRead(BaseModel):
    """Not yet exposed by any route; defined so that when it is, the shape is
    already minimal. The SQL injection exfiltrated `email` and `role` together,
    which is the pairing that tells an attacker which account to go after."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    email: Annotated[str, Field(max_length=EMAIL_MAX_LEN)]
