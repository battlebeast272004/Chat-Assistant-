"""Product data source discovery models."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class SourceType(str, Enum):
    SHOPIFY_PRODUCTS_JSON = "shopify_products_json"
    SHOPIFY_STOREFRONT_API = "shopify_storefront_api"
    WOOCOMMERCE_STORE_API = "woocommerce_store_api"
    JSON_LD = "json_ld"
    PRODUCT_SITEMAP = "product_sitemap"
    HTML_PRODUCT_PAGES = "html_product_pages"
    SITEMAP = "sitemap"
    XML_FEED = "xml_feed"


#: Lower number = higher extraction priority: Public API > JSON-LD > Sitemap/HTML.
SOURCE_PRIORITY: dict[SourceType, int] = {
    SourceType.SHOPIFY_PRODUCTS_JSON: 1,
    SourceType.WOOCOMMERCE_STORE_API: 1,
    SourceType.SHOPIFY_STOREFRONT_API: 1,   # needs a token, so never used for extraction here
    SourceType.JSON_LD: 2,
    SourceType.PRODUCT_SITEMAP: 3,
    SourceType.HTML_PRODUCT_PAGES: 3,       # product links found in homepage/catalog HTML
    SourceType.SITEMAP: 4,
    SourceType.XML_FEED: 5,                 # discovery only
}

EXTRACTABLE = {
    SourceType.SHOPIFY_PRODUCTS_JSON,
    SourceType.WOOCOMMERCE_STORE_API,
    SourceType.JSON_LD,
    SourceType.PRODUCT_SITEMAP,
    SourceType.HTML_PRODUCT_PAGES,
    SourceType.SITEMAP,
}

#: Sources whose products are read from individual product pages.
PAGE_SAMPLING = {SourceType.PRODUCT_SITEMAP, SourceType.HTML_PRODUCT_PAGES, SourceType.SITEMAP}


class DiscoveredSource(BaseModel):
    source_type: SourceType
    source_url: str
    accessible: bool
    requires_auth: bool
    limitations: list[str] = Field(default_factory=list)
    priority: int
    http_status: int | None = None
    item_count: int | None = Field(default=None, description="Items observed in the response (not the catalog size)")
    evidence: str | None = None
    sample_urls: list[str] = Field(default_factory=list, description="Candidate product page URLs (sitemaps only)")


class ProbeRecord(BaseModel):
    """Every outbound request made during discovery, for transparency and audit."""
    url: str
    purpose: str
    http_status: int | None = None
    error_code: str | None = None
    response_time_ms: int | None = None


class SourceDiscoveryResult(BaseModel):
    base_url: str | None
    platform: str
    sources: list[DiscoveredSource] = Field(default_factory=list)
    recommended_source: SourceType | None = None
    probes: list[ProbeRecord] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
