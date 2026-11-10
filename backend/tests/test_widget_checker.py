from __future__ import annotations

import pytest

from database.models import Platform
from models.widget import Feasibility, InstallMethod
from services import widget_checker as wc
from services.platform_detector import Confidence, PlatformDetectionResult
from services.url_validator import ErrorCode, FetchResult, ValidationResult

SCRIPT = "https://widget.assist.io/v1/widget.js"
API = "https://api.assist.io"


@pytest.fixture(autouse=True)
def widget_urls(monkeypatch):
    monkeypatch.setattr(wc, "WIDGET_SCRIPT_URL", SCRIPT)
    monkeypatch.setattr(wc, "WIDGET_API_ORIGIN", API)
    monkeypatch.setattr(wc, "WIDGET_FRAME_ORIGIN", "")


def home(html="<html></html>", headers=None, url="https://shop.example.com/", error_code=None, status=200):
    return FetchResult(
        result=ValidationResult(original_url=url, final_url=url, http_status=status, is_accessible=status == 200,
                                error_code=error_code),
        headers={k.lower(): v for k, v in (headers or {}).items()}, html=html)


def platform(name: str, conf: str = "high") -> PlatformDetectionResult:
    return PlatformDetectionResult(detected_platform=Platform(name), confidence=Confidence(conf), evidence=[], scores={})


def option(result, method):
    return next(o for o in result.options if o.method == method)


# ------------------------------------------------------------------ CSP
@pytest.mark.parametrize("policy,expected", [
    ("default-src 'self'", "blocks"),
    ("script-src 'self' https://widget.assist.io; connect-src 'self' https://api.assist.io", "allows"),
    ("script-src 'self' *.assist.io; connect-src *.assist.io", "allows"),
    ("script-src https:; connect-src https:", "allows"),
    ("script-src *; connect-src *", "allows"),
    ("script-src 'self' https://widget.assist.io", "allows"),                     # connect-src unrestricted
    ("script-src 'self' https://widget.assist.io/v1/; connect-src https://api.assist.io", "allows"),   # path prefix
    ("script-src 'self' https://widget.assist.io/v2/", "blocks"),                 # wrong path
    ("script-src 'self' https://widget.assist.io:8443", "blocks"),               # wrong port
    ("script-src 'self' http://widget.assist.io", "allows"),                      # http: source upgrades to https
    ("script-src 'nonce-abc' 'strict-dynamic' https://widget.assist.io", "unclear"),
    ("script-src 'none'", "blocks"),
    ("script-src https://widget.assist.io; connect-src 'self'", "blocks"),        # API blocked
    ("frame-ancestors 'self'; upgrade-insecure-requests", "allows"),
    ("script-src-elem https://widget.assist.io; script-src 'self'", "allows"),    # -elem takes precedence
])
def test_csp_verdicts(policy, expected):
    assert wc.analyse_csp({"content-security-policy": policy}, "").verdict == expected


def test_multiple_policies_must_all_allow():
    header = "script-src https://widget.assist.io, script-src 'self'"   # two policies joined by comma
    assert wc.analyse_csp({"content-security-policy": header}, "").verdict == "blocks"


def test_wildcard_does_not_match_apex():
    assert not wc._host_source_matches("*.assist.io", "https://assist.io/x.js")


def test_meta_csp_is_honoured():
    html = '<html><head><meta http-equiv="Content-Security-Policy" content="script-src \'self\'"></head></html>'
    csp = wc.analyse_csp({}, html)
    assert csp.verdict == "blocks" and csp.sources == ["meta"]


def test_report_only_is_not_enforced():
    csp = wc.analyse_csp({"content-security-policy-report-only": "default-src 'none'"}, "")
    assert csp.verdict == "report_only" and not csp.enforced


def test_inline_scripts_flag():
    assert wc.analyse_csp({"content-security-policy": "script-src 'self' 'nonce-x' 'unsafe-inline'"}, "").inline_scripts_allowed is False
    assert wc.analyse_csp({"content-security-policy": "script-src * 'unsafe-inline'"}, "").inline_scripts_allowed is True


def test_bot_challenge_csp_not_used():
    h = home("<title>Just a moment...</title>", {"content-security-policy": "default-src 'none'"},
             error_code=ErrorCode.BOT_PROTECTION, status=403)
    res = wc.assess_widget_installation(h, platform("unknown", "low"))
    assert res.csp.verdict == "not_checked"
    assert all(o.feasibility == Feasibility.REQUIRES_INVESTIGATION
               for o in res.options if o.method != InstallMethod.AGENCY_HANDOFF)


# ------------------------------------------------------------------ signals
GTM_SNIPPET = """<script>(function(w,d,s,l,i){w[l]=w[l]||[];j.src='https://www.googletagmanager.com/gtm.js?id='+i;
})(window,document,'script','dataLayer','GTM-ABC1234');</script>
<noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-ABC1234"></iframe></noscript>"""


def test_gtm_detected():
    res = wc.assess_widget_installation(home(GTM_SNIPPET), platform("custom", "medium"))
    assert res.signals.gtm_containers == ["GTM-ABC1234"]
    gtm = option(res, InstallMethod.GOOGLE_TAG_MANAGER)
    assert gtm.feasibility == Feasibility.LIKELY
    assert "Publish permission on GTM container GTM-ABC1234" in gtm.permissions_required


def test_gtag_only_is_not_gtm():
    html = '<script async src="https://www.googletagmanager.com/gtag/js?id=G-XYZ12345"></script>'
    res = wc.assess_widget_installation(home(html), platform("custom", "medium"))
    assert res.signals.gtm_containers == [] and res.signals.gtag_ids == ["G-XYZ12345"]
    gtm = option(res, InstallMethod.GOOGLE_TAG_MANAGER)
    assert gtm.feasibility == Feasibility.POSSIBLE and "not a GTM container" in gtm.evidence[0]


def test_gtm_mentioned_in_text_only_is_ignored():
    res = wc.assess_widget_installation(home("<p>We use gtm.js?id=GTM-TEXT999 in our blog</p>"), platform("custom"))
    assert res.signals.gtm_containers == []


def test_chat_consent_cache_signals():
    html = ('<script src="https://widget.intercom.io/widget/abc"></script>'
            '<script src="https://cdn.cookielaw.org/scripttemplates/otSDKStub.js"></script>')
    res = wc.assess_widget_installation(home(html, {"cf-cache-status": "HIT"}), platform("woocommerce"))
    s = res.signals
    assert s.existing_chat_widgets == ["Intercom"] and s.consent_managers == ["OneTrust"]
    assert s.page_cache == ["cf-cache-status: HIT"]
    assert any("Intercom" in r for r in option(res, InstallMethod.SCRIPT_TAG).risks)
    assert any("OneTrust" in r for r in option(res, InstallMethod.GOOGLE_TAG_MANAGER).risks)


# ------------------------------------------------------------------ methods per platform
def test_shopify_app_embed_recommended():
    res = wc.assess_widget_installation(home(), platform("shopify"))
    app = option(res, InstallMethod.CMS_PLUGIN_APP)
    assert app.feasibility == Feasibility.LIKELY and "app embed" in app.client_action_required
    assert res.recommended_method == InstallMethod.CMS_PLUGIN_APP
    assert any("Shopify store owner" in p for p in res.undetectable_permissions)


def test_woocommerce_plugin():
    res = wc.assess_widget_installation(home(), platform("woocommerce"))
    app = option(res, InstallMethod.CMS_PLUGIN_APP)
    assert app.feasibility == Feasibility.LIKELY
    assert app.permissions_required == ["WordPress Administrator (install_plugins capability)"]


def test_csp_block_downgrades_likely_to_possible():
    res = wc.assess_widget_installation(home(headers={"content-security-policy": "script-src 'self'"}), platform("shopify"))
    app = option(res, InstallMethod.CMS_PLUGIN_APP)
    assert app.feasibility == Feasibility.POSSIBLE
    assert any("Content-Security-Policy must be updated" in r for r in app.risks)


def test_low_confidence_platform_gets_no_plugin_route():
    res = wc.assess_widget_installation(home(), platform("unknown", "low"))
    assert option(res, InstallMethod.CMS_PLUGIN_APP).feasibility == Feasibility.REQUIRES_INVESTIGATION


def test_free_wix_domain():
    res = wc.assess_widget_installation(home(url="https://jane.wixsite.com/shop"), platform("wix"))
    st = option(res, InstallMethod.SCRIPT_TAG)
    assert st.feasibility == Feasibility.REQUIRES_INVESTIGATION and any("wixsite.com" in e for e in st.evidence)


def test_headless_nextjs_store():
    html = '<script id="__NEXT_DATA__" type="application/json">{}</script><img src="https://cdn.shopify.com/a.jpg">'
    res = wc.assess_widget_installation(home(html), platform("unknown", "low"))
    assert res.signals.headless_commerce and res.signals.frontend_framework.startswith("Next.js")
    assert option(res, InstallMethod.CMS_PLUGIN_APP).feasibility == Feasibility.REQUIRES_INVESTIGATION
    assert option(res, InstallMethod.AGENCY_HANDOFF).feasibility == Feasibility.LIKELY
    assert res.recommended_method == InstallMethod.AGENCY_HANDOFF


def test_gtm_without_container_not_recommended_over_agency():
    res = wc.assess_widget_installation(home(), platform("unknown", "low"))
    assert res.recommended_method == InstallMethod.AGENCY_HANDOFF


def test_every_option_has_required_fields_and_undetectable_permissions():
    res = wc.assess_widget_installation(home(GTM_SNIPPET), platform("magento"))
    assert {o.method for o in res.options} == set(InstallMethod)
    for o in res.options:
        assert o.client_action_required and o.feasibility in Feasibility and isinstance(o.evidence, list)
    assert any("GTM-ABC1234" in p for p in res.undetectable_permissions)
    assert any("Content-Security-Policy" in p for p in res.undetectable_permissions)


def test_placeholder_widget_url_noted(monkeypatch):
    monkeypatch.setattr(wc, "WIDGET_SCRIPT_URL", "https://widget.shopping-assistant.example/v1/widget.js")
    assert any("placeholder" in n for n in wc.assess_widget_installation(home(), platform("shopify")).notes)
