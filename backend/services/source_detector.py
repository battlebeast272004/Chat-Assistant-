"""Product data source discovery.

Every request goes through ``url_validator.validate_target`` (via
``ProbeContext.fetch``). That includes URLs taken from robots.txt, sitemap
indexes and sitemap entries, which are attacker-controlled input as far as
we're concerned. So every SSRF, timeout and size protection from Stage 2
applies to every hop.

Probe plan (at most ~12 requests, small parallelism, one overall deadline):

  Phase 0  homepage (the submitted URL) -> platform detection
  Phase 1  in parallel, depending on platform:
             shopify / unknown / custom   -> /products.json?limit=5
             woocommerce / unknown / custom -> /wp-json/wc/store/v1/products?per_page=5
             shopify      -> /collections/all.atom (product Atom feed)
             woocommerce  -> /?post_type=product&feed=rss2
             always       -> /robots.txt, /sitemap.xml
             catalog page -> only if the homepage has no JSON-LD Product
  Phase 2  sitemaps listed in robots.txt; product child sitemaps of an index;
           /sitemap_products_1.xml (Shopify) when no product sitemap was found;
           legacy Woo Store API path when v1 returned 404
"""

from __future__ import annotations

import json
import re
import threading
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup
from defusedxml import DefusedXmlException
from defusedxml.ElementTree import fromstring as safe_xml_fromstring
from xml.etree.ElementTree import ParseError

from database.models import Platform
from models.source import (
    EXTRACTABLE,
    PAGE_SAMPLING,
    SOURCE_PRIORITY,
    DiscoveredSource,
    ProbeRecord,
    SourceDiscoveryResult,
    SourceType,
)
from services.platform_detector import PlatformDetectionResult, detect_platform
from services.structured_data import count_jsonld_products
from services.url_validator import CLIENT_ERROR_CODES, ErrorCode, FetchResult, validate_target

DISCOVERY_BUDGET_S = 30.0
MIN_PROBE_TIME_S = 1.0
PROBE_WORKERS = 4
MAX_ROBOTS_BYTES = 512 * 1024
MAX_ROBOTS_SITEMAPS = 5
MAX_CHILD_SITEMAPS = 1
MAX_SAMPLE_URLS = 10
MAX_SITEMAP_DECOMPRESSED = 5 * 1024 * 1024

JSON_ACCEPT = "application/json"
XML_ACCEPT = "application/xml, text/xml;q=0.9, */*;q=0.5"

PRODUCT_URL_PATTERN = re.compile(r"/(products?|p|item|items|shop|catalog)/[^/?#]+", re.IGNORECASE)
NON_PRODUCT_PATH = re.compile(
    r"/(page/\d+|category|categories|tag|tags|cart|checkout|account|my-account|login|search|feed|wp-json)(/|$)",
    re.IGNORECASE,
)
AUTH_ERROR_CODES = {"rest_forbidden", "rest_not_logged_in", "rest_cannot_view", "woocommerce_rest_cannot_view"}
CATALOG_LINK_PATTERN = re.compile(r"^/(shop|products|catalog|collections/all|store)/?$", re.IGNORECASE)


# ======================================================================
# Probe context: deadline, cache and an audit log of every request
# ======================================================================
class ProbeContext:
    def __init__(self, budget_s: float = DISCOVERY_BUDGET_S):
        self.deadline = time.monotonic() + budget_s
        self.cache: dict[str, FetchResult] = {}
        self.probes: list[ProbeRecord] = []
        self._lock = threading.Lock()

    def extend(self, extra_s: float) -> None:
        self.deadline = max(self.deadline, time.monotonic() + extra_s)

    def remaining(self) -> float:
        return self.deadline - time.monotonic()

    def fetch(self, url: str, purpose: str, *, accept: str | None = None,
              max_bytes: int | None = None) -> FetchResult | None:
        with self._lock:
            if url in self.cache:
                return self.cache[url]
        remaining = self.remaining()
        if remaining < MIN_PROBE_TIME_S:
            with self._lock:
                self.probes.append(ProbeRecord(url=url, purpose=purpose, error_code="skipped_time_budget"))
            return None
        kwargs: dict[str, Any] = {"timeout_s": remaining, "accept": accept}
        if max_bytes is not None:
            kwargs["max_bytes"] = max_bytes
        result = validate_target(url, **kwargs)
        r = result.result
        with self._lock:
            self.cache[url] = result
            self.probes.append(ProbeRecord(
                url=r.normalized_url or url, purpose=purpose, http_status=r.http_status,
                error_code=r.error_code.value if r.error_code else None,
                response_time_ms=r.response_time_ms,
            ))
        return result

    def fetch_many(self, jobs: list[tuple[str, str, dict]]) -> dict[str, FetchResult | None]:
        """Run (url, purpose, kwargs) jobs in parallel; returns {url: result}."""
        unique = list(dict.fromkeys(j[0] for j in jobs))
        by_url = {j[0]: j for j in jobs}
        with ThreadPoolExecutor(max_workers=PROBE_WORKERS, thread_name_prefix="probe") as pool:
            futures = {u: pool.submit(self.fetch, u, by_url[u][1], **by_url[u][2]) for u in unique}
            return {u: f.result() for u, f in futures.items()}


# ======================================================================
# Helpers
# ======================================================================
def origin_of(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def _status_limitation(fetch: FetchResult | None, what: str) -> list[str]:
    """Explain why a probe isn't usable, based only on what was observed."""
    if fetch is None:
        return [f"{what} was not probed: time budget exhausted."]
    r = fetch.result
    if r.error_code == ErrorCode.BOT_PROTECTION:
        return [f"{what} is behind bot protection (HTTP {r.http_status})."]
    if r.error_code in CLIENT_ERROR_CODES:
        return [f"{what} blocked by SSRF policy: {r.error}"]
    if r.http_status == 404:
        return [f"{what} not found (HTTP 404)."]
    if r.http_status == 401:
        return [f"{what} requires authentication (HTTP 401)."]
    if r.http_status == 403:
        return [f"{what} refused access (HTTP 403): it may require authentication or block automated clients."]
    if r.http_status is not None and r.http_status >= 400:
        return [f"{what} returned HTTP {r.http_status}."]
    if r.error:
        return [f"{what} could not be fetched: {r.error}"]
    return []


def _requires_auth(fetch: FetchResult | None) -> bool:
    """True only on explicit evidence: HTTP 401 or a known auth error code.
    A bare 403 is ambiguous (WAF, geo-block, auth) so it does not count."""
    if not fetch:
        return False
    if fetch.result.http_status == 401:
        return True
    data = parse_json(fetch)
    return isinstance(data, dict) and str(data.get("code", "")).lower() in AUTH_ERROR_CODES


def _looks_like_html(fetch: FetchResult) -> bool:
    head = fetch.body[:512].lstrip().lower()
    return "html" in fetch.content_type.lower() or head.startswith((b"<!doctype html", b"<html"))


def parse_json(fetch: FetchResult | None) -> Any:
    if not fetch or not fetch.text:
        return None
    try:
        return json.loads(fetch.text)
    except (json.JSONDecodeError, RecursionError):
        return None


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def parse_sitemap(fetch: FetchResult) -> tuple[str | None, list[str], str | None]:
    """Return (kind, locs, error). kind is 'index' or 'urlset'.

    Uses defusedxml (blocks XXE, entity expansion, external DTDs). Gzipped
    sitemaps are decompressed with a hard output cap.
    """
    if _looks_like_html(fetch):
        return None, [], "Returned an HTML page instead of an XML sitemap (likely a soft 404)."
    data = fetch.body
    if data[:2] == b"\x1f\x8b":
        try:
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            data = d.decompress(data, MAX_SITEMAP_DECOMPRESSED)
            if d.unconsumed_tail:
                return None, [], "Gzipped sitemap exceeds the decompression limit."
        except zlib.error:
            return None, [], "Gzipped sitemap is corrupt."
    try:
        root = safe_xml_fromstring(data)
    except (ParseError, DefusedXmlException, ValueError) as exc:
        return None, [], f"Sitemap XML could not be parsed safely ({type(exc).__name__})."
    kind = _local(root.tag)
    if kind not in ("sitemapindex", "urlset"):
        return None, [], f"Not a sitemap (root element <{kind}>)."
    locs = []
    for child in root:
        for el in child:
            if _local(el.tag) == "loc" and el.text and el.text.strip():
                locs.append(el.text.strip())
                break
    return ("index" if kind == "sitemapindex" else "urlset"), locs, None


def _robots_sitemaps(text: str, base: str) -> list[str]:
    found = []
    for line in text.splitlines()[:5000]:
        m = re.match(r"^\s*sitemap\s*:\s*(\S+)", line, re.IGNORECASE)
        if m:
            url = urljoin(base + "/", m.group(1))
            if url not in found:
                found.append(url)
    return found[:MAX_ROBOTS_SITEMAPS]


def _storefront_indicator(html: str) -> str | None:
    """Look for a public Storefront API access token. The token itself is never returned."""
    if not html:
        return None
    soup = BeautifulSoup(html, "html.parser")
    if soup.find("meta", attrs={"name": "shopify-checkout-api-token"}):
        return "shopify-checkout-api-token meta tag present"
    if re.search(r"[\"']storefront(Access)?Token[\"']\s*:\s*[\"'][0-9a-f]{32}[\"']", html, re.IGNORECASE):
        return "Storefront access token found in inline script"
    return None


def _catalog_candidate(platform: str, base: str, html: str) -> str | None:
    if platform == Platform.SHOPIFY.value:
        return base + "/collections/all"
    if platform == Platform.WOOCOMMERCE.value:
        return base + "/shop/"
    if not html:
        return None
    soup = BeautifulSoup(html, "html.parser")
    host = urlsplit(base).netloc
    for a in soup.find_all("a", href=True):
        absolute = urljoin(base + "/", a["href"])
        parts = urlsplit(absolute)
        if parts.netloc == host and CATALOG_LINK_PATTERN.match(parts.path):
            return f"{base}{parts.path}"
    return None


def is_product_like(url: str) -> bool:
    parts = urlsplit(url)
    return bool(PRODUCT_URL_PATTERN.search(parts.path)) and not NON_PRODUCT_PATH.search(parts.path)


def product_links(html: str, page_url: str, limit: int = MAX_SAMPLE_URLS) -> list[str]:
    """Same-host links whose path looks like a product page, in document order."""
    if not html:
        return []
    host = urlsplit(page_url).netloc
    soup = BeautifulSoup(html, "html.parser")
    found: list[str] = []
    for a in soup.find_all("a", href=True):
        parts = urlsplit(urljoin(page_url, a["href"]))
        if parts.scheme not in ("http", "https") or parts.netloc != host or parts.query:
            continue
        url = f"{parts.scheme}://{parts.netloc}{parts.path}"
        if is_product_like(url) and url not in found and url.rstrip("/") != page_url.rstrip("/"):
            found.append(url)
            if len(found) >= limit:
                break
    return found


def _source(stype: SourceType, url: str, accessible: bool, *, requires_auth: bool = False,
            limitations: list[str] | None = None, fetch: FetchResult | None = None,
            item_count: int | None = None, evidence: str | None = None,
            sample_urls: list[str] | None = None) -> DiscoveredSource:
    return DiscoveredSource(
        source_type=stype, source_url=url, accessible=accessible, requires_auth=requires_auth,
        limitations=limitations or [], priority=SOURCE_PRIORITY[stype],
        http_status=fetch.result.http_status if fetch else None,
        item_count=item_count, evidence=evidence, sample_urls=sample_urls or [],
    )


# ======================================================================
# Individual source evaluators
# ======================================================================
def _eval_shopify_json(url: str, fetch: FetchResult | None) -> DiscoveredSource:
    data = parse_json(fetch)
    final_path = urlsplit(fetch.result.final_url or "").path if fetch else ""
    if fetch and fetch.result.http_status == 200 and isinstance(data, dict) and isinstance(data.get("products"), list):
        return _source(
            SourceType.SHOPIFY_PRODUCTS_JSON, url, True, fetch=fetch, item_count=len(data["products"]),
            evidence=f"Returned {len(data['products'])} product(s) with limit=5.",
            limitations=[
                "Response does not include a currency; prices are in the shop's currency, which is not stated here.",
                "Paginated (max 250 per page); no inventory quantities, only a per-variant 'available' flag.",
                "Only products published to the Online Store channel are listed.",
            ],
        )
    lims = _status_limitation(fetch, "/products.json")
    if final_path.rstrip("/") == "/password":
        lims = ["Store is password-protected (redirected to /password)."]
    elif fetch and fetch.result.http_status == 200:
        lims = ["/products.json responded but not with a Shopify products JSON payload."]
    return _source(SourceType.SHOPIFY_PRODUCTS_JSON, url, False, requires_auth=_requires_auth(fetch),
                   fetch=fetch, limitations=lims)


def _eval_woo_api(url: str, fetch: FetchResult | None) -> DiscoveredSource:
    data = parse_json(fetch)
    if fetch and fetch.result.http_status == 200 and isinstance(data, list) and all(isinstance(x, dict) for x in data):
        return _source(
            SourceType.WOOCOMMERCE_STORE_API, url, True, fetch=fetch, item_count=len(data),
            evidence=f"Returned {len(data)} product(s) with per_page=5.",
            limitations=[
                "Public Store API lists only published, catalog-visible products.",
                "Paginated (max 100 per page).",
            ],
        )
    lims = _status_limitation(fetch, "WooCommerce Store API")
    if fetch and fetch.result.http_status == 200 and not lims:
        lims = ["Endpoint responded but not with a product list (JSON array)."]
    if isinstance(data, dict) and data.get("code"):
        lims.append(f"API error code: {str(data['code'])[:80]}")
    return _source(SourceType.WOOCOMMERCE_STORE_API, url, False, requires_auth=_requires_auth(fetch),
                   fetch=fetch, limitations=lims)


def _eval_jsonld(url: str, fetch: FetchResult | None, label: str) -> tuple[DiscoveredSource, list[str]]:
    if not fetch or not fetch.html:
        lims = _status_limitation(fetch, label) or [f"{label} returned no HTML."]
        return _source(SourceType.JSON_LD, url, False, fetch=fetch, limitations=lims), []
    count, warnings = count_jsonld_products(fetch.html)
    if count:
        return _source(SourceType.JSON_LD, url, True, fetch=fetch, item_count=count,
                       evidence=f"{count} schema.org Product node(s) in JSON-LD on the {label}.",
                       limitations=warnings), warnings
    return _source(SourceType.JSON_LD, url, False, fetch=fetch,
                   limitations=[f"No schema.org Product JSON-LD on the {label}.", *warnings]), warnings


def _eval_feed(url: str, fetch: FetchResult | None, label: str) -> DiscoveredSource:
    if not fetch or fetch.result.http_status != 200 or not fetch.body:
        return _source(SourceType.XML_FEED, url, False, fetch=fetch,
                       limitations=_status_limitation(fetch, label) or [f"{label} returned an empty body."])
    if _looks_like_html(fetch):
        return _source(SourceType.XML_FEED, url, False, fetch=fetch,
                       limitations=[f"{label} returned an HTML page, not a feed (feed likely disabled)."])
    try:
        root = safe_xml_fromstring(fetch.body)
    except (ParseError, DefusedXmlException, ValueError):
        return _source(SourceType.XML_FEED, url, False, fetch=fetch,
                       limitations=[f"{label} is not well-formed XML (or was rejected by the safe XML parser)."])
    kind = _local(root.tag)
    entries = [el for el in root.iter() if _local(el.tag) in ("entry", "item")]
    has_price = any(_local(el.tag) in ("price", "variant") for el in root.iter())
    lims = [] if has_price else ["Feed entries contain no price or availability fields."]
    if kind not in ("feed", "rss"):
        lims.append(f"Unexpected root element <{kind}>.")
    return _source(SourceType.XML_FEED, url, kind in ("feed", "rss"), fetch=fetch, item_count=len(entries),
                   evidence=f"{'Atom' if kind == 'feed' else kind.upper()} feed with {len(entries)} "
                            f"entr{'y' if len(entries) == 1 else 'ies'}.",
                   limitations=lims)


# ======================================================================
# Main entry point
# ======================================================================
def discover_sources(
    raw_url: str, ctx: ProbeContext | None = None
) -> tuple[FetchResult, PlatformDetectionResult | None, SourceDiscoveryResult, ProbeContext]:
    ctx = ctx or ProbeContext()
    home = ctx.fetch(raw_url, "homepage")
    assert home is not None  # first call always has budget
    v = home.result

    if v.error_code in CLIENT_ERROR_CODES:
        return home, None, SourceDiscoveryResult(base_url=None, platform=Platform.UNKNOWN.value,
                                                 probes=ctx.probes, notes=[v.error or "URL rejected."]), ctx
    if v.http_status is None:  # DNS / connection / TLS failure: nothing to probe
        return home, None, SourceDiscoveryResult(
            base_url=None, platform=Platform.UNKNOWN.value, probes=ctx.probes,
            notes=[f"Site could not be reached ({v.error_code.value if v.error_code else 'error'}); no probes run."]), ctx

    platform_result = detect_platform(home.html, home.headers, home.cookie_names, v.final_url,
                                      blocked=v.error_code == ErrorCode.BOT_PROTECTION)
    return home, platform_result, discover_from_home(raw_url, home, platform_result, ctx), ctx


def discover_from_home(
    raw_url: str, home: FetchResult, platform_result: PlatformDetectionResult | None, ctx: ProbeContext
) -> SourceDiscoveryResult:
    """Run every discovery probe, given a homepage that was already fetched.
    The orchestrator uses this directly so each stage has its own error boundary."""
    v = home.result
    if v.error_code in CLIENT_ERROR_CODES or v.http_status is None:
        return SourceDiscoveryResult(base_url=None, platform=Platform.UNKNOWN.value, probes=ctx.probes,
                                     notes=["Homepage was not fetched; no probes run."])
    platform = platform_result.detected_platform.value if platform_result else Platform.UNKNOWN.value
    base = origin_of(v.final_url or v.normalized_url or raw_url)
    open_platform = platform in (Platform.UNKNOWN.value, Platform.CUSTOM.value)
    notes: list[str] = []
    sources: list[DiscoveredSource] = []

    # ---------------- Phase 1 ----------------
    shopify_json = f"{base}/products.json?limit=5"
    woo_v1 = f"{base}/wp-json/wc/store/v1/products?per_page=5"
    shopify_feed = f"{base}/collections/all.atom"
    woo_feed = f"{base}/?post_type=product&feed=rss2"
    robots = f"{base}/robots.txt"
    sitemap = f"{base}/sitemap.xml"

    home_products, _ = count_jsonld_products(home.html)
    catalog = None if home_products else _catalog_candidate(platform, base, home.html)
    if catalog and catalog.rstrip("/") == (v.final_url or "").rstrip("/"):
        catalog = None

    jobs: list[tuple[str, str, dict]] = [
        (robots, "robots.txt", {"max_bytes": MAX_ROBOTS_BYTES}),
        (sitemap, "sitemap", {"accept": XML_ACCEPT}),
    ]
    if platform == Platform.SHOPIFY.value or open_platform:
        jobs.append((shopify_json, "shopify products.json", {"accept": JSON_ACCEPT}))
    if platform == Platform.WOOCOMMERCE.value or open_platform:
        jobs.append((woo_v1, "woocommerce store api", {"accept": JSON_ACCEPT}))
    if platform == Platform.SHOPIFY.value:
        jobs.append((shopify_feed, "shopify product atom feed", {"accept": XML_ACCEPT}))
    if platform == Platform.WOOCOMMERCE.value:
        jobs.append((woo_feed, "woocommerce product rss feed", {"accept": XML_ACCEPT}))
    if catalog:
        jobs.append((catalog, "catalog page", {}))
    results = ctx.fetch_many(jobs)

    # ---------------- Platform APIs ----------------
    if shopify_json in results:
        sources.append(_eval_shopify_json(shopify_json, results[shopify_json]))
    if platform == Platform.SHOPIFY.value:
        indicator = _storefront_indicator(home.html)
        if indicator:
            sources.append(_source(
                SourceType.SHOPIFY_STOREFRONT_API, f"{base}/api/<version>/graphql.json", False,
                requires_auth=True, evidence=indicator,
                limitations=["Requires the X-Shopify-Storefront-Access-Token header; access was not verified in this stage.",
                             "The token value is deliberately not included in this report."],
            ))
    if woo_v1 in results:
        woo_fetch = results[woo_v1]
        if woo_fetch and woo_fetch.result.http_status == 404:
            legacy = f"{base}/wp-json/wc/store/products?per_page=5"
            legacy_fetch = ctx.fetch(legacy, "woocommerce store api (legacy path)", accept=JSON_ACCEPT)
            legacy_src = _eval_woo_api(legacy, legacy_fetch)
            sources.append(legacy_src if legacy_src.accessible else _eval_woo_api(woo_v1, woo_fetch))
        else:
            sources.append(_eval_woo_api(woo_v1, woo_fetch))

    # ---------------- JSON-LD (homepage / catalog) ----------------
    home_label = "homepage" if urlsplit(v.final_url or "").path in ("", "/") else "submitted page"
    home_src, home_warn = _eval_jsonld(v.final_url or raw_url, home, home_label)
    if catalog:
        cat_src, _ = _eval_jsonld(catalog, results.get(catalog), "catalog page")
        sources.extend([s for s in (home_src, cat_src) if s.accessible] or [home_src, cat_src])
    else:
        sources.append(home_src)

    # ---------------- Sitemaps ----------------
    sitemap_urls: list[str] = [sitemap]
    robots_fetch = results.get(robots)
    if robots_fetch and robots_fetch.result.http_status == 200 and robots_fetch.text:
        listed = _robots_sitemaps(robots_fetch.text, base)
        sitemap_urls = list(dict.fromkeys(listed + [sitemap]))
        if listed:
            notes.append(f"robots.txt lists {len(listed)} sitemap(s).")
    extra = [(u, "sitemap (from robots.txt)", {"accept": XML_ACCEPT}) for u in sitemap_urls if u not in results]
    if extra:
        results.update(ctx.fetch_many(extra))

    product_sitemaps: list[str] = []
    for sm_url in sitemap_urls:
        sm_fetch = results.get(sm_url)
        if not sm_fetch or sm_fetch.result.http_status != 200:
            sources.append(_source(SourceType.SITEMAP, sm_url, False, fetch=sm_fetch,
                                   limitations=_status_limitation(sm_fetch, "Sitemap")))
            continue
        kind, locs, error = parse_sitemap(sm_fetch)
        if error:
            sources.append(_source(SourceType.SITEMAP, sm_url, False, fetch=sm_fetch, limitations=[error]))
            continue
        if kind == "index":
            children = [u for u in locs if "product" in u.lower()]
            product_sitemaps.extend(children)
            sources.append(_source(
                SourceType.SITEMAP, sm_url, True, fetch=sm_fetch, item_count=len(locs),
                evidence=f"Sitemap index with {len(locs)} child sitemap(s); {len(children)} look product-specific.",
                limitations=[] if children else ["No child sitemap is product-specific; product URLs can't be told apart from other pages."],
            ))
        else:
            samples = [u for u in locs if is_product_like(u)][:MAX_SAMPLE_URLS]
            sources.append(_source(
                SourceType.SITEMAP, sm_url, True, fetch=sm_fetch, item_count=len(locs), sample_urls=samples,
                evidence=f"URL set with {len(locs)} URL(s); {len(samples)} sampled URL(s) match product URL patterns.",
                limitations=["Sitemaps list URLs only; product data must be read from each page."],
            ))

    # Prefer same-host, shortest-path product sitemaps (skips locale copies like /es-US/sitemap_products_1.xml).
    base_host = urlsplit(base).netloc
    product_sitemaps = sorted(
        dict.fromkeys(product_sitemaps),
        key=lambda u: (urlsplit(u).netloc != base_host, urlsplit(u).path.count("/"), len(u)),
    )[:MAX_CHILD_SITEMAPS]
    if not product_sitemaps and platform == Platform.SHOPIFY.value:
        product_sitemaps = [f"{base}/sitemap_products_1.xml"]
    if product_sitemaps:
        child_results = ctx.fetch_many([(u, "product sitemap", {"accept": XML_ACCEPT}) for u in product_sitemaps])
        for ps_url, ps_fetch in child_results.items():
            if not ps_fetch or ps_fetch.result.http_status != 200:
                sources.append(_source(SourceType.PRODUCT_SITEMAP, ps_url, False, fetch=ps_fetch,
                                       limitations=_status_limitation(ps_fetch, "Product sitemap")))
                continue
            kind, locs, error = parse_sitemap(ps_fetch)
            if error or kind != "urlset":
                sources.append(_source(SourceType.PRODUCT_SITEMAP, ps_url, False, fetch=ps_fetch,
                                       limitations=[error or "Expected a URL set, got a sitemap index."]))
                continue
            # Product sitemaps often start with the homepage or collection URLs; keep only product-like paths.
            samples = [u for u in locs if is_product_like(u)][:MAX_SAMPLE_URLS]
            sources.append(_source(
                SourceType.PRODUCT_SITEMAP, ps_url, True, fetch=ps_fetch, item_count=len(locs), sample_urls=samples,
                evidence=f"Product sitemap with {len(locs)} URL(s).",
                limitations=["Sitemaps list URLs only; product details must be read from each product page."],
            ))

    # ---------------- HTML product links (homepage / catalog) ----------------
    link_pages = [(v.final_url or raw_url, home, home_label)]
    if catalog:
        link_pages.insert(0, (catalog, results.get(catalog), "catalog page"))
    for page_url, page_fetch, label in link_pages:
        links = product_links(page_fetch.html, page_fetch.result.final_url or page_url) if page_fetch else []
        if links:
            sources.append(_source(
                SourceType.HTML_PRODUCT_PAGES, page_url, True, fetch=page_fetch, item_count=len(links),
                sample_urls=links, evidence=f"{len(links)} product-like link(s) found on the {label}.",
                limitations=["Product URLs identified by URL pattern; data is read only from structured "
                             "data (JSON-LD / OpenGraph) on each product page."],
            ))
            break

    # ---------------- Feeds ----------------
    if shopify_feed in results:
        sources.append(_eval_feed(shopify_feed, results[shopify_feed], "Shopify product Atom feed"))
    if woo_feed in results:
        sources.append(_eval_feed(woo_feed, results[woo_feed], "WooCommerce product RSS feed"))
    notes.append("Merchant/Google Shopping and CSV feeds have no standard public URL; "
                 "they can't be discovered without the merchant providing the location.")

    if v.error_code == ErrorCode.BOT_PROTECTION:
        notes.append("Homepage is behind bot protection; some probes may be blocked too.")
    if home_warn:
        notes.extend(home_warn)

    sources.sort(key=lambda s: (s.priority, not s.accessible))
    recommended = next((s.source_type for s in sources if s.accessible and s.source_type in EXTRACTABLE
                        and (s.source_type not in PAGE_SAMPLING or s.sample_urls)), None)
    return SourceDiscoveryResult(base_url=base, platform=platform, sources=sources,
                                 recommended_source=recommended, probes=ctx.probes, notes=notes)
