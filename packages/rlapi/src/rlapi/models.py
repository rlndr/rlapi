"""Domain model for the inventory/orders API.

Design notes that carry security weight later in PLAN.md:

- **Money is integer cents.** No floats anywhere near a price or total.
- **`OrderItem.unit_price_cents` is denormalised on purpose.** It records the
  price *at the time of order*, so a later product price change cannot rewrite
  order history. Historical integrity is an audit property, not just a
  correctness one.
- **`ON DELETE` is explicit on every foreign key** -- `CASCADE` where the child
  has no meaning without the parent, `RESTRICT` where deleting the parent would
  destroy history. Defaulting these is how orphan rows and silent history loss
  happen.
- **CHECK constraints are the database-layer backstop**, not the control.
  Step 11's negative-quantity attack must be rejected by the API before it ever
  reaches here; `stock_qty >= 0` exists so that a bug in that layer produces an
  error instead of corrupt data. Note the asymmetry worth remembering: SQLite
  enforces CHECK constraints by default but **not** foreign keys (see `db.py`).
- **`AuditLog` is append-only by convention only.** SQLite cannot enforce that
  without triggers; step 6 adds them when the audit log starts carrying
  authorization decisions.
"""

import enum
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Final

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    String,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

EMAIL_MAX_LEN: Final = 320  # RFC 5321 local-part + domain ceiling
SKU_MAX_LEN: Final = 64
NAME_MAX_LEN: Final = 200


def _enum_values(enum_class: type[enum.Enum]) -> Sequence[str]:
    """Store enum *values*, not member names.

    SQLAlchemy stores `member.name` by default, so `Role.CUSTOMER` would land in
    the database as `'CUSTOMER'` while the API, the JWT `roles` claim and this
    code all say `'customer'`. Step 5 compares a token claim against this
    column; a silent case mismatch there fails open or closed depending on which
    side of the comparison is normalised, and neither is a property to leave to
    chance.
    """
    return [str(member.value) for member in enum_class]


def strict_enum(enum_class: type[enum.Enum], name: str) -> Enum:
    """A genuinely constrained enum column.

    `create_constraint=True` is the load-bearing argument. SQLAlchemy defaults
    it to **False** (since 1.4), so `Enum(...)` alone emits a bare `VARCHAR`
    with no CHECK -- and SQLite does not enforce VARCHAR length either. Verified
    at step 1: before this fix, `users.role` accepted `'root'`, `''`, and a
    32-character string in a `VARCHAR(8)` column.

    That matters because `users.role` is an authorization input. The API layer
    is the control; this constraint is the backstop for when the API has a bug.
    """
    return Enum(
        enum_class,
        name=name,
        native_enum=False,
        create_constraint=True,
        validate_strings=True,
        values_callable=_enum_values,
    )


def utcnow() -> datetime:
    """Timezone-aware UTC now.

    Explicitly aware: SQLite stores no timezone, so a naive datetime here is
    indistinguishable from local time on read. Token `exp`/`nbf` comparisons in
    step 4 depend on this being right, and ruff's DTZ rules enforce it.
    """
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class Role(enum.StrEnum):
    """Authorization roles, ordered least to most privileged.

    The ordering is documentation only -- step 5 derives permissions from an
    explicit policy table, not from comparing enum positions. Implying
    privilege from ordinal position is how role hierarchies acquire accidental
    escalation paths.
    """

    CUSTOMER = "customer"
    CLERK = "clerk"
    MANAGER = "manager"
    ADMIN = "admin"


class OrderStatus(enum.StrEnum):
    DRAFT = "draft"
    PLACED = "placed"
    PAID = "paid"
    SHIPPED = "shipped"
    CANCELLED = "cancelled"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(EMAIL_MAX_LEN), unique=True, index=True)
    role: Mapped[Role] = mapped_column(strict_enum(Role, "role"), default=Role.CUSTOMER)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=func.now()
    )

    orders: Mapped[list["Order"]] = relationship(back_populates="customer")

    def __repr__(self) -> str:
        return f"User(id={self.id!r}, email={self.email!r}, role={self.role!r})"


class Product(Base):
    __tablename__ = "products"
    __table_args__ = (
        CheckConstraint("price_cents >= 0", name="ck_products_price_nonneg"),
        CheckConstraint("stock_qty >= 0", name="ck_products_stock_nonneg"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    sku: Mapped[str] = mapped_column(String(SKU_MAX_LEN), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(NAME_MAX_LEN))
    price_cents: Mapped[int] = mapped_column(default=0)
    stock_qty: Mapped[int] = mapped_column(default=0)

    def __repr__(self) -> str:
        return f"Product(id={self.id!r}, sku={self.sku!r}, stock_qty={self.stock_qty!r})"


class Order(Base):
    __tablename__ = "orders"
    __table_args__ = (
        CheckConstraint("total_cents >= 0", name="ck_orders_total_nonneg"),
        # Step 5's row gate filters on customer_id. Indexed because an
        # authorization filter runs on every single read.
        Index("ix_orders_customer_status", "customer_id", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    # RESTRICT: deleting a user who has orders would orphan order history.
    customer_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), index=True
    )
    status: Mapped[OrderStatus] = mapped_column(
        strict_enum(OrderStatus, "order_status"), default=OrderStatus.DRAFT
    )
    total_cents: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=func.now()
    )

    customer: Mapped[User] = relationship(back_populates="orders")
    items: Mapped[list["OrderItem"]] = relationship(
        back_populates="order", cascade="all, delete-orphan", passive_deletes=True
    )

    def __repr__(self) -> str:
        return f"Order(id={self.id!r}, customer_id={self.customer_id!r}, status={self.status!r})"


class OrderItem(Base):
    __tablename__ = "order_items"
    __table_args__ = (
        CheckConstraint("qty > 0", name="ck_order_items_qty_positive"),
        CheckConstraint("unit_price_cents >= 0", name="ck_order_items_price_nonneg"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    # CASCADE: a line item has no meaning without its order.
    order_id: Mapped[int] = mapped_column(ForeignKey("orders.id", ondelete="CASCADE"), index=True)
    # RESTRICT: a product that has been ordered must not vanish from history.
    product_id: Mapped[int] = mapped_column(
        ForeignKey("products.id", ondelete="RESTRICT"), index=True
    )
    qty: Mapped[int]
    unit_price_cents: Mapped[int]

    order: Mapped[Order] = relationship(back_populates="items")
    product: Mapped[Product] = relationship()

    def __repr__(self) -> str:
        return f"OrderItem(id={self.id!r}, order_id={self.order_id!r}, qty={self.qty!r})"


class AuditLog(Base):
    """Authorization decisions and mutations. Populated from step 6.

    `actor_sub` is the token's `sub` claim, never a value supplied by the
    client. `decision` records denials as well as allows -- a log that only
    contains successes cannot answer "what did they try?".
    """

    __tablename__ = "audit_log"
    __table_args__ = (Index("ix_audit_log_ts_actor", "ts", "actor_sub"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=func.now(), index=True
    )
    actor_sub: Mapped[str | None] = mapped_column(String(255), index=True)
    action: Mapped[str] = mapped_column(String(100))
    resource: Mapped[str] = mapped_column(String(255))
    decision: Mapped[str] = mapped_column(String(20))
    request_id: Mapped[str | None] = mapped_column(String(64), index=True)

    def __repr__(self) -> str:
        return f"AuditLog(id={self.id!r}, action={self.action!r}, decision={self.decision!r})"
