from __future__ import annotations

from database.models import Platform
from services.platform_detector import Confidence, detect_platform

SHOPIFY_HTML = """<html><head>
<meta name="shopify-checkout-api-token" content="abc123">
<link rel="stylesheet" href="//store.com/cdn/shop/t/4/assets/base.css">
<script src="https://cdn.shopify.com/shopifycloud/storefront.js"></script>
<script>Shopify.shop = "demo.myshopify.com";</script>
</head><body><div id="shopify-section-header" class="shopify-section"></div></body></html>"""

WOO_HTML = """<html><head>
<meta name="generator" content="WordPress 6.6">
<meta name="generator" content="WooCommerce 9.3.1">
<link rel="stylesheet" href="https://shop.co.uk/wp-content/plugins/woocommerce/assets/css/woocommerce.css">
<script>var wc_add_to_cart_params = {"ajax_url":"/wp-admin/admin-ajax.php"};</script>
</head><body class="home woocommerce-page woocommerce-js"></body></html>"""

WIX_HTML = """<html><head>
<meta name="generator" content="Wix.com Website Builder">
<script src="https://static.parastorage.com/services/wix-thunderbolt/dist/main.js"></script>
</head><body><img src="https://static.wixstatic.com/media/abc.jpg"></body></html>"""

MAGENTO_HTML = """<html><head>
<script src="https://m2.example.com/static/version1712345678/frontend/Magento/luma/en_US/requirejs/require.js"></script>
<script type="text/x-magento-init">{"*": {"Magento_Ui/js/core/app": {}}}</script>
</head><body><div data-mage-init='{"dropdown":{}}'></div></body></html>"""

BIGCOMMERCE_HTML = """<html><head>
<meta name="platform" content="bigcommerce.stencil">
<script src="https://cdn11.bigcommerce.com/s-abc123/stencil/theme.js"></script>
<script>var BCData = {"csrf_token":"x"};</script>
</head><body></body></html>"""

CUSTOM_HTML = """<html><head>
<meta property="og:type" content="product">
<meta property="product:price:amount" content="19.99">
<script type="application/ld+json">{"@context":"https://schema.org","@type":"Product","name":"Mug"}</script>
</head><body><a href="/cart">Cart</a><button>Add to cart</button></body></html>"""


def test_shopify_high_confidence_with_headers():
    r = detect_platform(SHOPIFY_HTML, headers={"X-ShopId": "123", "Powered-By": "Shopify"},
                        final_url="https://store.com/")
    assert r.detected_platform == Platform.SHOPIFY
    assert r.confidence == Confidence.HIGH
    signals = {e.signal for e in r.evidence}
    assert {"shopify.header.x-shopid", "shopify.asset.cdn", "shopify.markup.shopify-object"} <= signals


def test_woocommerce_detected():
    r = detect_platform(WOO_HTML, cookie_names=["woocommerce_items_in_cart"])
    assert r.detected_platform == Platform.WOOCOMMERCE
    assert r.confidence == Confidence.HIGH
    assert any(e.platform == "wordpress" for e in r.evidence)


def test_wix_detected():
    r = detect_platform(WIX_HTML, headers={"x-wix-request-id": "1.2.3"})
    assert r.detected_platform == Platform.WIX and r.confidence == Confidence.HIGH


def test_magento_detected():
    r = detect_platform(MAGENTO_HTML)
    assert r.detected_platform == Platform.MAGENTO
    assert r.confidence in (Confidence.HIGH, Confidence.MEDIUM)


def test_bigcommerce_detected():
    r = detect_platform(BIGCOMMERCE_HTML)
    assert r.detected_platform == Platform.BIGCOMMERCE and r.confidence == Confidence.HIGH


def test_header_only_detection_is_medium():
    r = detect_platform("", headers={"x-shopid": "1"})
    assert r.detected_platform == Platform.SHOPIFY
    assert r.confidence == Confidence.MEDIUM   # one source only -> not high


def test_custom_store():
    r = detect_platform(CUSTOM_HTML)
    assert r.detected_platform == Platform.CUSTOM
    assert all(e.platform == "generic_commerce" for e in r.evidence)


def test_empty_page_is_unknown():
    r = detect_platform("<html><head><title>Hello</title></head><body>Welcome</body></html>")
    assert r.detected_platform == Platform.UNKNOWN
    assert r.confidence == Confidence.LOW
    assert r.evidence == []


def test_sparse_signal_is_unknown_not_guessed():
    # A single image hotlinked from Shopify's CDN is not enough to call it Shopify.
    html = '<html><body><img src="https://cdn.shopify.com/s/files/logo.png"></body></html>'
    r = detect_platform(html)
    assert r.detected_platform == Platform.UNKNOWN
    assert r.evidence and r.evidence[0].signal == "shopify.asset.cdn"
    assert any("Weak shopify signals" in n for n in r.notes)


def test_conflicting_strong_signals_return_unknown():
    r = detect_platform(SHOPIFY_HTML + MAGENTO_HTML)
    assert r.detected_platform == Platform.UNKNOWN
    assert r.confidence == Confidence.LOW
    assert any("Conflicting" in n for n in r.notes)


def test_minor_secondary_signal_does_not_cause_conflict():
    # WooCommerce store that embeds a Shopify Buy Button image.
    html = WOO_HTML.replace("</body>", '<img src="https://cdn.shopify.com/s/files/x.png"></body>')
    r = detect_platform(html)
    assert r.detected_platform == Platform.WOOCOMMERCE


def test_wordpress_without_woocommerce_is_not_woocommerce():
    html = """<html><head><meta name="generator" content="WordPress 6.6">
    <link rel="stylesheet" href="/wp-content/themes/x/style.css"></head><body>Blog</body></html>"""
    r = detect_platform(html)
    assert r.detected_platform == Platform.UNKNOWN
    assert "woocommerce" not in r.scores
    assert any("no WooCommerce" in n for n in r.notes)


def test_text_mention_is_not_an_asset_signal():
    html = "<html><body><p>We moved away from cdn.shopify.com last year.</p></body></html>"
    assert detect_platform(html).evidence == []


def test_evidence_detail_is_truncated():
    long_value = "x" * 500
    r = detect_platform("", headers={"x-shopid": long_value})
    assert len(r.evidence[0].detail) <= 120


def test_blocked_flag_adds_note():
    r = detect_platform("<title>Just a moment...</title>", blocked=True)
    assert r.detected_platform == Platform.UNKNOWN
    assert any("bot-protection" in n for n in r.notes)
