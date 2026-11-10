"""Deterministic e-commerce platform detection from a single fetched page.

How it works
------------
1. Every rule is a discrete, explainable *signal*: a platform, where it is
   looked for (header, cookie, meta tag, asset URL, inline markup, hostname),
   a regex, and a weight:
       3 = strong:   specific to the platform, rarely seen elsewhere
       2 = medium:   typical of the platform, but can occasionally appear elsewhere
       1 = weak:     supporting context only
2. A rule fires at most once. Each platform's score is the sum of its fired
   weights, and each fired rule is reported as an evidence item.
3. Decision:
   - top score < 3                         -> not enough evidence (Unknown, or Custom, see 4)
   - runner-up >= 3 and >= half of the top  -> conflicting signals -> Unknown
   - top >= 6 from >= 2 source types       -> high confidence
   - otherwise                              -> medium confidence
4. Custom: no known platform reached the threshold, but the page shows
   generic commerce markup (schema.org Product/Offer, product meta tags,
   add-to-cart controls) worth >= 3 from >= 2 distinct signals.

Asset rules only look at real ``src``/``href`` attributes, not page text, so a
blog post that *mentions* "cdn.shopify.com" doesn't count as a Shopify signal.
No network requests are made here; the detector only reads what the fetcher
already returned.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import Literal
from urllib.parse import urlsplit

from bs4 import BeautifulSoup
from pydantic import BaseModel

from database.models import Platform

STRONG, MEDIUM, WEAK = 3, 2, 1
DETECTION_THRESHOLD = 3
HIGH_CONFIDENCE_SCORE = 6
CUSTOM_THRESHOLD = 3
MAX_DETAIL_LEN = 120

Source = Literal["header", "cookie", "meta", "asset", "markup", "hostname"]


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Evidence(BaseModel):
    platform: str      # a Platform value, "wordpress" (context) or "generic_commerce"
    signal: str        # stable machine id, e.g. "shopify.header.x-shopid"
    description: str   # human-readable explanation
    source: Source
    detail: str        # what actually matched (truncated, untrusted text)
    weight: int


class PlatformDetectionResult(BaseModel):
    detected_platform: Platform
    confidence: Confidence
    evidence: list[Evidence]
    scores: dict[str, int]
    notes: list[str] = []


@dataclass(frozen=True)
class Rule:
    platform: str
    signal: str
    description: str
    source: Source
    pattern: re.Pattern
    weight: int
    key: str | None = None  # header name / meta name, depending on source


def _r(p: str) -> re.Pattern:
    return re.compile(p, re.IGNORECASE)


_ANY = _r(r".+")

RULES: list[Rule] = [
    # ---------------- Shopify ----------------
    Rule("shopify", "shopify.header.x-shopid", "X-ShopId response header", "header", _ANY, STRONG, "x-shopid"),
    Rule("shopify", "shopify.header.x-shopify-stage", "X-Shopify-Stage response header", "header", _ANY, STRONG, "x-shopify-stage"),
    Rule("shopify", "shopify.header.sorting-hat", "X-Sorting-Hat-ShopId response header", "header", _ANY, STRONG, "x-sorting-hat-shopid"),
    Rule("shopify", "shopify.header.powered-by", "Powered-By: Shopify header", "header", _r(r"shopify"), STRONG, "powered-by"),
    Rule("shopify", "shopify.cookie", "Shopify session cookies", "cookie", _r(r"^(_shopify_[a-z]+|secure_customer_sig|cart_sig)$"), MEDIUM),
    Rule("shopify", "shopify.meta.checkout-token", "shopify-checkout-api-token meta tag", "meta", _ANY, STRONG, "shopify-checkout-api-token"),
    Rule("shopify", "shopify.meta.digital-wallet", "shopify-digital-wallet meta tag", "meta", _ANY, STRONG, "shopify-digital-wallet"),
    Rule("shopify", "shopify.asset.cdn", "Assets served from cdn.shopify.com", "asset", _r(r"//cdn\.shopify\.com/"), MEDIUM),
    Rule("shopify", "shopify.asset.cdn-shop", "Assets served from the /cdn/shop/ path", "asset", _r(r"/cdn/shop/"), MEDIUM),
    Rule("shopify", "shopify.asset.shopifycloud", "shopifycloud scripts", "asset", _r(r"/shopifycloud/"), MEDIUM),
    Rule("shopify", "shopify.markup.shopify-object", "Shopify.shop / ShopifyAnalytics JS globals", "markup", _r(r"\bShopify\.shop\s*=|\bShopifyAnalytics\.meta\b"), STRONG),
    Rule("shopify", "shopify.markup.section", "shopify-section theme markup", "markup", _r(r"class=[\"'][^\"']*\bshopify-section\b"), MEDIUM),
    Rule("shopify", "shopify.hostname", "Hosted on *.myshopify.com", "hostname", _r(r"\.myshopify\.com$"), STRONG),

    # ---------------- WooCommerce ----------------
    Rule("woocommerce", "woo.meta.generator", "Meta generator WooCommerce", "meta", _r(r"woocommerce"), STRONG, "generator"),
    Rule("woocommerce", "woo.asset.plugin", "wp-content/plugins/woocommerce assets", "asset", _r(r"/wp-content/plugins/woocommerce[/-]"), STRONG),
    Rule("woocommerce", "woo.markup.js-params", "WooCommerce JS params (wc_add_to_cart_params etc.)", "markup", _r(r"\b(wc_add_to_cart_params|woocommerce_params|wc_cart_fragments_params)\b"), STRONG),
    Rule("woocommerce", "woo.markup.body-class", "woocommerce CSS classes", "markup", _r(r"class=[\"'][^\"']*\bwoocommerce(-page|-no-js|-js)?\b"), MEDIUM),
    Rule("woocommerce", "woo.markup.store-api", "WooCommerce Store API link", "markup", _r(r"/wp-json/wc/(store|v\d)"), MEDIUM),
    Rule("woocommerce", "woo.cookie", "WooCommerce cookies", "cookie", _r(r"^(woocommerce_[a-z_]+|wp_woocommerce_session_.*)$"), STRONG),
    # WordPress context: counts towards WooCommerce only if a direct Woo signal also fired.
    Rule("wordpress", "wp.meta.generator", "Meta generator WordPress", "meta", _r(r"wordpress"), WEAK, "generator"),
    Rule("wordpress", "wp.asset.paths", "wp-content / wp-includes assets", "asset", _r(r"/wp-(content|includes)/"), WEAK),
    Rule("wordpress", "wp.header.api-link", "Link header to /wp-json/", "header", _r(r"/wp-json/"), WEAK, "link"),

    # ---------------- Wix ----------------
    Rule("wix", "wix.header.request-id", "X-Wix-Request-Id response header", "header", _ANY, STRONG, "x-wix-request-id"),
    Rule("wix", "wix.header.server", "Server: Pepyaka (Wix)", "header", _r(r"pepyaka"), STRONG, "server"),
    Rule("wix", "wix.meta.generator", "Meta generator Wix.com Website Builder", "meta", _r(r"wix\.com"), STRONG, "generator"),
    Rule("wix", "wix.asset.parastorage", "Assets from static.parastorage.com", "asset", _r(r"//static\.parastorage\.com/"), STRONG),
    Rule("wix", "wix.asset.wixstatic", "Media from static.wixstatic.com", "asset", _r(r"//static\.wixstatic\.com/"), MEDIUM),
    Rule("wix", "wix.markup.bootstrap", "Wix bootstrap data (wixBiSession / wix-warmup-data)", "markup", _r(r"\bwixBiSession\b|id=[\"']wix-warmup-data[\"']"), STRONG),
    Rule("wix", "wix.hostname", "Hosted on *.wixsite.com", "hostname", _r(r"\.wixsite\.com$"), STRONG),

    # ---------------- Magento / Adobe Commerce ----------------
    Rule("magento", "magento.header.cache", "X-Magento-* response headers", "header", _ANY, STRONG, "x-magento-cache-debug"),
    Rule("magento", "magento.header.tags", "X-Magento-Tags response header", "header", _ANY, STRONG, "x-magento-tags"),
    Rule("magento", "magento.meta.generator", "Meta generator Magento", "meta", _r(r"magento"), STRONG, "generator"),
    Rule("magento", "magento.markup.x-magento-init", "text/x-magento-init script blocks (Magento 2)", "markup", _r(r"type=[\"']text/x-magento-init[\"']"), STRONG),
    Rule("magento", "magento.markup.mage-init", "data-mage-init attributes (Magento 2)", "markup", _r(r"\bdata-mage-init="), MEDIUM),
    Rule("magento", "magento.markup.mage-cookies", "Mage.Cookies JS (Magento 1)", "markup", _r(r"\bMage\.Cookies\b"), STRONG),
    Rule("magento", "magento.asset.static-frontend", "Magento 2 static/frontend asset paths", "asset", _r(r"/static/(version\d+/)?frontend/[^/]+/[^/]+/"), STRONG),
    Rule("magento", "magento.asset.skin-frontend", "Magento 1 skin/frontend or js/mage asset paths", "asset", _r(r"/skin/frontend/|/js/mage/"), MEDIUM),
    Rule("magento", "magento.cookie", "Magento cookies", "cookie", _r(r"^(x-magento-vary|mage-cache-sessid|mage-cache-storage|mage-messages)$"), MEDIUM),

    # ---------------- BigCommerce ----------------
    Rule("bigcommerce", "bc.asset.cdn", "Assets from cdnXX.bigcommerce.com", "asset", _r(r"//cdn\d*\.bigcommerce\.com/"), STRONG),
    Rule("bigcommerce", "bc.meta.platform", "Meta platform bigcommerce.stencil", "meta", _r(r"bigcommerce"), STRONG, "platform"),
    Rule("bigcommerce", "bc.markup.bcdata", "BCData JS global", "markup", _r(r"\bvar\s+BCData\b|\bwindow\.BCData\b"), STRONG),
    Rule("bigcommerce", "bc.markup.stencil", "Stencil theme utilities", "markup", _r(r"\bstencil-utils\b|\bstencilBootstrap\b"), MEDIUM),
    Rule("bigcommerce", "bc.cookie", "BigCommerce cookies", "cookie", _r(r"^(SHOP_SESSION_TOKEN|fornax_anonymousId|athena_short_visit_number)$"), MEDIUM),
    Rule("bigcommerce", "bc.hostname", "Hosted on *.mybigcommerce.com", "hostname", _r(r"\.mybigcommerce\.com$"), STRONG),

    # ---------------- Generic commerce (used to decide Custom) ----------------
    Rule("generic_commerce", "commerce.jsonld.product", "schema.org Product/Offer in JSON-LD", "markup",
         _r(r"<script[^>]+application/ld\+json[^>]*>[^<]*\"@type\"\s*:\s*\[?\s*\"(Product|Offer|AggregateOffer|ProductGroup)\""), MEDIUM),
    Rule("generic_commerce", "commerce.microdata.product", "schema.org/Product microdata", "markup", _r(r"itemtype=[\"']https?://schema\.org/(Product|Offer)[\"']"), MEDIUM),
    Rule("generic_commerce", "commerce.meta.og-product", "og:type product", "meta", _r(r"^product"), MEDIUM, "og:type"),
    Rule("generic_commerce", "commerce.meta.price", "product:price:amount meta tag", "meta", _ANY, MEDIUM, "product:price:amount"),
    Rule("generic_commerce", "commerce.markup.add-to-cart", "Add-to-cart / basket controls", "markup", _r(r"add[\s_-]?to[\s_-]?(cart|bag|basket)"), WEAK),
    Rule("generic_commerce", "commerce.asset.cart-link", "Links to /cart, /basket or /checkout", "asset", _r(r"^(https?://[^/]+)?/(cart|basket|checkout)(/|\?|$)"), WEAK),
]

KNOWN_PLATFORMS = ("shopify", "woocommerce", "wix", "magento", "bigcommerce")


# --------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------
@dataclass
class _PageFeatures:
    headers: dict[str, str]
    cookies: list[str]
    meta: dict[str, list[str]]
    assets: list[str]
    markup: str
    hostname: str


def _extract(html: str, headers: dict[str, str], cookie_names: list[str], final_url: str | None) -> _PageFeatures:
    meta: dict[str, list[str]] = defaultdict(list)
    assets: list[str] = []
    if html:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all("meta"):
            name = (tag.get("name") or tag.get("property") or "").strip().lower()
            content = tag.get("content")
            if name and content is not None:
                meta[name].append(str(content))
        for tag in soup.find_all(["script", "link", "img", "a", "iframe", "source"]):
            for attr in ("src", "href", "data-src"):
                value = tag.get(attr)
                if isinstance(value, str) and value:
                    assets.append(value.strip())
    return _PageFeatures(
        headers={k.lower(): v for k, v in headers.items()},
        cookies=list(cookie_names),
        meta=dict(meta),
        assets=assets,
        markup=html or "",
        hostname=(urlsplit(final_url).hostname or "") if final_url else "",
    )


def _short(text: str) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= MAX_DETAIL_LEN else text[: MAX_DETAIL_LEN - 1] + "…"


def _match(rule: Rule, page: _PageFeatures) -> str | None:
    """Return the matched detail string if the rule fires, otherwise None."""
    if rule.source == "header":
        value = page.headers.get(rule.key or "")
        if value is not None and rule.pattern.search(value):
            return f"{rule.key}: {value}"
    elif rule.source == "cookie":
        for name in page.cookies:
            if rule.pattern.search(name):
                return f"cookie {name}"
    elif rule.source == "meta":
        for value in page.meta.get(rule.key or "", []):
            if rule.pattern.search(value):
                return f'<meta {rule.key}="{value}">'
    elif rule.source == "asset":
        for url in page.assets:
            if rule.pattern.search(url):
                return url
    elif rule.source == "markup":
        m = rule.pattern.search(page.markup)
        if m:
            return m.group(0)
    elif rule.source == "hostname":
        if page.hostname and rule.pattern.search(page.hostname):
            return page.hostname
    return None


# --------------------------------------------------------------------------
# Decision
# --------------------------------------------------------------------------
def detect_platform(
    html: str,
    headers: dict[str, str] | None = None,
    cookie_names: list[str] | None = None,
    final_url: str | None = None,
    blocked: bool = False,
) -> PlatformDetectionResult:
    page = _extract(html or "", headers or {}, cookie_names or [], final_url)

    fired: list[Evidence] = []
    for rule in RULES:
        detail = _match(rule, page)
        if detail is not None:
            fired.append(Evidence(
                platform=rule.platform, signal=rule.signal, description=rule.description,
                source=rule.source, detail=_short(detail), weight=rule.weight,
            ))

    scores: dict[str, int] = {p: 0 for p in KNOWN_PLATFORMS}
    sources: dict[str, set[str]] = defaultdict(set)
    for ev in fired:
        if ev.platform in scores:
            scores[ev.platform] += ev.weight
            sources[ev.platform].add(ev.source)

    # WordPress signals only support WooCommerce; they're never enough on their own.
    wp_evidence = [e for e in fired if e.platform == "wordpress"]
    if scores["woocommerce"] > 0:
        for ev in wp_evidence:
            scores["woocommerce"] += ev.weight
            sources["woocommerce"].add(ev.source)

    commerce = [e for e in fired if e.platform == "generic_commerce"]
    commerce_score = sum(e.weight for e in commerce)

    notes: list[str] = []
    if blocked:
        notes.append("The page looks like a bot-protection challenge, so detection may be incomplete.")
    if not html:
        notes.append(
            "No HTML was available to inspect; only response headers were checked."
            if headers else "No response was received, so there was nothing to inspect."
        )
    if wp_evidence and scores["woocommerce"] == 0:
        notes.append("WordPress detected, but no WooCommerce signals were found.")

    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    (top, top_score), (runner, runner_score) = ranked[0], ranked[1]

    def result(platform: Platform, confidence: Confidence) -> PlatformDetectionResult:
        # Platform evidence first (strongest first), then context and commerce signals.
        order = {p: i for i, p in enumerate([platform.value, *KNOWN_PLATFORMS, "wordpress", "generic_commerce"])}
        fired.sort(key=lambda e: (order.get(e.platform, 99), -e.weight))
        return PlatformDetectionResult(
            detected_platform=platform, confidence=confidence, evidence=fired,
            scores={k: v for k, v in scores.items() if v} | ({"generic_commerce": commerce_score} if commerce_score else {}),
            notes=notes,
        )

    if top_score >= DETECTION_THRESHOLD:
        if runner_score >= DETECTION_THRESHOLD and runner_score * 2 >= top_score:
            notes.append(
                f"Conflicting signals: {top} (score {top_score}) and {runner} (score {runner_score}). "
                "Not choosing between them."
            )
            return result(Platform.UNKNOWN, Confidence.LOW)
        strong = top_score >= HIGH_CONFIDENCE_SCORE and len(sources[top]) >= 2
        if runner_score:
            notes.append(f"Minor {runner} signals (score {runner_score}) were outweighed by {top}.")
        return result(Platform(top), Confidence.HIGH if strong else Confidence.MEDIUM)

    if top_score > 0:
        notes.append(
            f"Weak {top} signals only (score {top_score}, needs {DETECTION_THRESHOLD}); not enough to identify the platform."
        )

    if commerce_score >= CUSTOM_THRESHOLD and len(commerce) >= 2:
        notes.append("Commerce markup found but no known platform matched; treating as a custom store.")
        return result(Platform.CUSTOM, Confidence.MEDIUM if commerce_score >= 5 else Confidence.LOW)

    if not fired:
        notes.append("No platform or commerce signals found on this page.")
    return result(Platform.UNKNOWN, Confidence.LOW)
