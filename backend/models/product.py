"""Normalized product schema + extraction result models.

``Product`` is the strict, public contract. ``extra="forbid"`` means a mapper
can't quietly add unexpected fields. Every optional field defaults to None, and
None means "the source did not state this". It never means zero, false or
"unknown but probably X".
"""

from __future__ import annotations

import math
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_PRODUCTS = 5

#: schema.org ItemAvailability values. Anything else becomes None, never a guess.
AVAILABILITY_VALUES = (
    "InStock", "OutOfStock", "PreOrder", "PreSale", "BackOrder", "Discontinued",
    "LimitedAvailability", "InStoreOnly", "OnlineOnly", "SoldOut", "MadeToOrder", "Reserved",
)


class Product(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    description: str | None = None
    price: float | None = None
    currency: str | None = Field(default=None, pattern=r"^[A-Z]{3}$")
    category: str | None = None
    specifications: dict[str, Any] = Field(default_factory=dict)
    image_url: str | None = None
    product_url: str | None = None
    availability: str | None = None

    @field_validator("price")
    @classmethod
    def _finite_non_negative(cls, v: float | None) -> float | None:
        if v is None:
            return None
        if not math.isfinite(v) or v < 0:
            raise ValueError("price must be a finite, non-negative number")
        return v

    @field_validator("image_url", "product_url")
    @classmethod
    def _http_only(cls, v: str | None) -> str | None:
        if v is not None and not v.lower().startswith(("http://", "https://")):
            raise ValueError("URL must be http(s)")
        return v

    @field_validator("availability")
    @classmethod
    def _known_availability(cls, v: str | None) -> str | None:
        if v is not None and v not in AVAILABILITY_VALUES:
            raise ValueError(f"availability must be one of {AVAILABILITY_VALUES}")
        return v


PRODUCT_FIELDS: tuple[str, ...] = tuple(Product.model_fields)


def _is_present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (dict, list, str)) and len(value) == 0:
        return False
    return True


def compute_field_coverage(products: list[Product]) -> dict[str, float]:
    """Percent (0-100, 1 decimal) of items where each field is present.
    ``specifications`` counts as present only if it is non-empty."""
    if not products:
        return {f: 0.0 for f in PRODUCT_FIELDS}
    total = len(products)
    return {
        f: round(100.0 * sum(_is_present(getattr(p, f)) for p in products) / total, 1)
        for f in PRODUCT_FIELDS
    }


class ExtractionAttempt(BaseModel):
    source_type: str
    source_url: str
    products_extracted: int
    error: str | None = None


class ExtractionResult(BaseModel):
    source_type: str | None = None          # source the products came from
    source_url: str | None = None
    products: list[Product] = Field(default_factory=list, max_length=MAX_PRODUCTS)
    items_extracted: int = 0
    field_coverage: dict[str, float] = Field(default_factory=lambda: compute_field_coverage([]))
    attempts: list[ExtractionAttempt] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
