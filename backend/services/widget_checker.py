"""Widget installation assessment (deterministic, evidence-based, passive).

No extra requests are made. Everything is read from the homepage response that
was already fetched (HTML + headers) plus the platform and product-source
results from earlier stages.

What we CAN observe publicly:
  * Content-Security-Policy (header + <meta>): would the browser load our
    script and let it call our API? This applies to every install method.
  * GTM containers, gtag-only setups, front-end frameworks (headless),
    existing chat widgets, consent managers, page caches, free hosted domains.

What we CANNOT observe (always listed in ``undetectable_permissions``):
  admin roles, GTM publish rights, theme/code deploy access, the ability to
  change HTTP headers, hosting restrictions, internal vendor approval.

Feasibility:
  likely                 = positive evidence the route exists; nothing observed blocks it
  possible               = route normally exists, but evidence is indirect or a fixable blocker was seen
  requires_investigation = blocker, unclear CSP, missing HTML, or no supported route found
"""

from __future__ import annotations

import os
import re
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from database.models import Platform
from models.source import SourceDiscoveryResult, SourceType
from models.widget import (
    FEASIBILITY_RANK,
    CSPAnalysis,
    CSPDirectiveCheck,
    Feasibility,
    InstallationOption,
    InstallMethod,
    PageSignals,
    WidgetAssessment,
)
from services.platform_detector import Confidence, PlatformDetectionResult
from services.url_validator import ErrorCode, FetchResult

# Our widget's endpoints. Set these to the real CDN/API in deployment so the
# CSP check tests the actual URLs.
WIDGET_SCRIPT_URL = os.environ.get("WIDGET_SCRIPT_URL", "https://widget.shopping-assistant.example/v1/widget.js")
WIDGET_API_ORIGIN = os.environ.get("WIDGET_API_ORIGIN", "https://api.shopping-assistant.example")
WIDGET_FRAME_ORIGIN = os.environ.get("WIDGET_FRAME_ORIGIN", "")  # empty = widget does not use an iframe

L, P, R = Feasibility.LIKELY, Feasibility.POSSIBLE, Feasibility.REQUIRES_INVESTIGATION

# Preference order when several methods share the best feasibility (least client friction first).
METHOD_PREFERENCE = [InstallMethod.CMS_PLUGIN_APP, InstallMethod.GOOGLE_TAG_MANAGER,
                     InstallMethod.SCRIPT_TAG, InstallMethod.AGENCY_HANDOFF]


# ======================================================================
# Content-Security-Policy evaluation
# ======================================================================
_FALLBACKS = {
    "script": ("script-src-elem", "script-src", "default-src"),
    "connect": ("connect-src", "default-src"),
    "frame": ("frame-src", "child-src", "default-src"),
}
_DEFAULT_PORTS = {"http": 80, "https": 443}


def parse_csp(value: str) -> list[dict[str, list[str]]]:
    """A header value can hold several policies separated by commas (e.g.
    repeated headers joined together). Each policy maps directive -> tokens.
    Per the spec, only the first occurrence of a directive counts."""
    policies = []
    for raw_policy in value.split(","):
        policy: dict[str, list[str]] = {}
        for part in raw_policy.split(";"):
            tokens = part.strip().split()
            if tokens:
                name = tokens[0].lower()
                policy.setdefault(name, tokens[1:])
        if policy:
            policies.append(policy)
    return policies


def _host_source_matches(token: str, url: str) -> bool:
    target = urlsplit(url)
    t_scheme, t_host = target.scheme.lower(), (target.hostname or "").lower()
    t_port = target.port or _DEFAULT_PORTS.get(t_scheme)
    m = re.match(r"^(?:(?P<scheme>[a-z][a-z0-9+.-]*)://)?(?P<host>\*|(?:\*\.)?[a-z0-9.-]+)(?::(?P<port>\*|\d+))?(?P<path>/.*)?$",
                 token.lower())
    if not m:
        return False
    scheme, host, port, path = m.group("scheme"), m.group("host"), m.group("port"), m.group("path")
    if scheme:
        # http: in the policy also matches https (CSP3 upgrade rule)
        if not (scheme == t_scheme or (scheme == "http" and t_scheme == "https")):
            return False
    elif t_scheme not in ("http", "https"):
        return False
    if host == "*":
        pass
    elif host.startswith("*."):
        if not t_host.endswith(host[1:]):
            return False
    elif host != t_host:
        return False
    if port != "*":
        expected = int(port) if port else _DEFAULT_PORTS.get(scheme or t_scheme)
        if t_port != expected and not (port is None and scheme == "http" and t_port == 443):
            return False
    if path:
        t_path = target.path or "/"
        if path.endswith("/"):
            if not t_path.startswith(path):
                return False
        elif t_path != path:
            return False
    return True


def _evaluate(policy: dict[str, list[str]], kind: str, url: str) -> CSPDirectiveCheck:
    directive = next((d for d in _FALLBACKS[kind] if d in policy), None)
    if directive is None:
        return CSPDirectiveCheck(directive="(none)", target=url, allowed=True,
                                 reason=f"No {kind}-related directive or default-src; not restricted.")
    tokens = [t.lower() for t in policy[directive]]
    if kind == "script" and "'strict-dynamic'" in tokens:
        return CSPDirectiveCheck(directive=directive, target=url, allowed=None,
                                 reason="'strict-dynamic' ignores host allowlists: the widget loads only if injected "
                                        "by an already-trusted (nonce/hash) script. Needs manual verification.")
    if not tokens or tokens == ["'none'"]:
        return CSPDirectiveCheck(directive=directive, target=url, allowed=False, reason=f"{directive} is 'none'.")
    scheme = urlsplit(url).scheme
    for t in tokens:
        if t == "*" or t == f"{scheme}:" or (t == "http:" and scheme == "https"):
            return CSPDirectiveCheck(directive=directive, target=url, allowed=True, reason=f"Allowed by {t}.")
        if not t.startswith("'") and _host_source_matches(t, url):
            return CSPDirectiveCheck(directive=directive, target=url, allowed=True, reason=f"Allowed by {t}.")
    return CSPDirectiveCheck(directive=directive, target=url, allowed=False,
                             reason=f"{directive} does not include the widget origin.")


def _inline_allowed(policy: dict[str, list[str]]) -> bool:
    directive = next((d for d in ("script-src-elem", "script-src", "default-src") if d in policy), None)
    if directive is None:
        return True
    tokens = [t.lower() for t in policy[directive]]
    has_nonce_or_hash = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for t in tokens)
    return "'unsafe-inline'" in tokens and not has_nonce_or_hash and "'strict-dynamic'" not in tokens


def analyse_csp(headers: dict[str, str], html: str) -> CSPAnalysis:
    analysis = CSPAnalysis()
    raw_policies: list[str] = []
    if headers.get("content-security-policy"):
        raw_policies.append(headers["content-security-policy"])
        analysis.sources.append("header")
    if html:
        soup = BeautifulSoup(html, "html.parser")
        for meta in soup.find_all("meta", attrs={"http-equiv": re.compile(r"^content-security-policy$", re.I)}):
            if meta.get("content"):
                raw_policies.append(str(meta["content"]))
                analysis.sources.append("meta")
    report_only = bool(headers.get("content-security-policy-report-only"))
    analysis.report_only = report_only

    policies = [p for raw in raw_policies for p in parse_csp(raw)]
    # A policy that only restricts things like frame-ancestors / upgrade-insecure-requests doesn't affect us.
    if not policies:
        analysis.verdict = "report_only" if report_only else "no_csp"
        if report_only:
            analysis.present = True
            analysis.notes.append("Only a Report-Only policy is present: violations are reported, not blocked.")
        return analysis

    analysis.present = analysis.enforced = True
    targets = [("script", WIDGET_SCRIPT_URL), ("connect", WIDGET_API_ORIGIN.rstrip("/") + "/")]
    if WIDGET_FRAME_ORIGIN:
        targets.append(("frame", WIDGET_FRAME_ORIGIN.rstrip("/") + "/"))

    results: list[bool | None] = []
    for kind, url in targets:
        # Every enforced policy must allow it.
        checks = [_evaluate(p, kind, url) for p in policies]
        worst = next((c for c in checks if c.allowed is False), None) or \
            next((c for c in checks if c.allowed is None), None) or checks[0]
        analysis.checks.append(worst)
        results.append(worst.allowed)
    analysis.inline_scripts_allowed = all(_inline_allowed(p) for p in policies)

    if any(r is False for r in results):
        analysis.verdict = "blocks"
    elif any(r is None for r in results):
        analysis.verdict = "unclear"
    else:
        analysis.verdict = "allows"
    if not analysis.inline_scripts_allowed:
        analysis.notes.append("Inline scripts are restricted: use an external script with data-attributes "
                              "for configuration, not an inline init snippet.")
    if "upgrade-insecure-requests" in {d for p in policies for d in p}:
        analysis.notes.append("upgrade-insecure-requests is set: all widget URLs must be HTTPS.")
    return analysis


# ======================================================================
# Page signals
# ======================================================================
_GTM_RE = re.compile(r"(?:gtm\.js\?id=|ns\.html\?id=|['\"]dataLayer['\"]\s*,\s*['\"])(GTM-[A-Z0-9]{4,12})\b")
_GTAG_RE = re.compile(r"googletagmanager\.com/gtag/js\?id=((?:G|AW|UA|DC)-[A-Z0-9-]{4,20})", re.I)

CHAT_WIDGETS = {
    "Intercom": r"widget\.intercom\.io|js\.intercomcdn\.com",
    "Zendesk": r"static\.zdassets\.com|ekr\.zdassets\.com",
    "Tidio": r"code\.tidio\.co",
    "Gorgias": r"config\.gorgias\.chat|gorgias-chat",
    "Drift": r"js\.driftt\.com",
    "LiveChat": r"cdn\.livechatinc\.com",
    "HubSpot Chat": r"js\.usemessages\.com|js\.hs-scripts\.com",
    "Crisp": r"client\.crisp\.chat",
    "tawk.to": r"embed\.tawk\.to",
    "Freshchat": r"wchat\.freshchat\.com|fw-cdn\.com",
    "Help Scout Beacon": r"beacon-v2\.helpscout\.net",
    "Shopify Inbox": r"shopify-chat|shopify_chat",
}
CONSENT_MANAGERS = {
    "OneTrust": r"cdn\.cookielaw\.org|optanon",
    "Cookiebot": r"consent\.cookiebot\.com",
    "Usercentrics": r"usercentrics\.eu",
    "iubenda": r"cdn\.iubenda\.com",
    "Didomi": r"sdk\.privacy-center\.org",
    "Quantcast Choice": r"cmp\.quantcast\.com",
    "CookieYes": r"cdn-cookieyes\.com",
    "Termly": r"app\.termly\.io",
}
FRAMEWORKS = [
    ("Shopify Hydrogen", r"hydrogen|@shopify/hydrogen"),
    ("Next.js", r"id=[\"']__NEXT_DATA__[\"']|/_next/static/"),
    ("Nuxt", r"window\.__NUXT__|/_nuxt/"),
    ("Gatsby", r"id=[\"']___gatsby[\"']"),
    ("Remix", r"__remixContext"),
    ("SvelteKit", r"__sveltekit|/_app/immutable/"),
    ("Angular", r"\sng-version=[\"']"),
]
CACHE_HEADERS = {
    "cf-cache-status": r"^hit$", "x-cache": r"\bhit\b", "x-litespeed-cache": r"^hit", "x-proxy-cache": r"^hit$",
    "x-kinsta-cache": r"^hit$", "x-sucuri-cache": r"^hit$", "x-wp-super-cache": r".", "x-varnish-cache": r"^hit$",
    "x-fastly-cache": r"\bhit\b", "x-vercel-cache": r"^hit$", "x-nextjs-cache": r"^hit$",
}


def _script_corpus(html: str) -> str:
    """Script srcs, link hrefs and inline script bodies, so text mentions in the page body don't count."""
    if not html:
        return ""
    soup = BeautifulSoup(html, "html.parser")
    parts = []
    for tag in soup.find_all(["script", "link", "iframe", "noscript"]):
        for attr in ("src", "href", "id"):
            if tag.get(attr):
                parts.append(str(tag[attr]))
        if tag.name in ("script", "noscript") and tag.string:
            parts.append(tag.string[:200_000])
    return "\n".join(parts)


def collect_signals(home: FetchResult, platform: str, discovery: SourceDiscoveryResult | None) -> PageSignals:
    html, headers = home.html or "", home.headers or {}
    corpus = _script_corpus(html)
    s = PageSignals()
    s.gtm_containers = list(dict.fromkeys(_GTM_RE.findall(corpus)))
    s.gtag_ids = list(dict.fromkeys(m.upper() for m in _GTAG_RE.findall(corpus)))
    s.existing_chat_widgets = [name for name, pat in CHAT_WIDGETS.items() if re.search(pat, corpus, re.I)]
    s.consent_managers = [name for name, pat in CONSENT_MANAGERS.items() if re.search(pat, corpus, re.I)]
    s.frontend_framework = next((name for name, pat in FRAMEWORKS if re.search(pat, html, re.I)), None)
    s.page_cache = [f"{h}: {headers[h]}" for h, pat in CACHE_HEADERS.items()
                    if h in headers and re.search(pat, headers[h], re.I)]
    host = urlsplit(home.result.final_url or "").hostname or ""
    s.free_hosted_domain = host.endswith((".wixsite.com", ".myshopify.com", ".mybigcommerce.com"))

    shopify_backend = bool(discovery and any(
        src.source_type == SourceType.SHOPIFY_PRODUCTS_JSON and src.accessible for src in discovery.sources)) \
        or "cdn.shopify.com" in corpus
    theme_platform = platform in (Platform.SHOPIFY.value, Platform.WOOCOMMERCE.value, Platform.MAGENTO.value,
                                  Platform.BIGCOMMERCE.value, Platform.WIX.value)
    # Headless: a JS framework front end with no theme-based platform detected.
    s.headless_commerce = bool(s.frontend_framework) and (not theme_platform or s.frontend_framework == "Shopify Hydrogen")
    if s.headless_commerce and shopify_backend and s.frontend_framework != "Shopify Hydrogen":
        s.frontend_framework = f"{s.frontend_framework} (Shopify backend)"
    return s


# ======================================================================
# Method assessments
# ======================================================================
def _csp_effect(csp: CSPAnalysis) -> tuple[Feasibility | None, list[str], list[str]]:
    """Return (cap on feasibility, evidence, risks) caused by CSP."""
    if csp.verdict == "blocks":
        blocked = [c for c in csp.checks if c.allowed is False]
        return P, [f"CSP blocks the widget: {c.directive} - {c.reason}" for c in blocked], \
            ["The site's Content-Security-Policy must be updated to allow the widget's script and API origins."]
    if csp.verdict == "unclear":
        return R, [f"CSP: {c.reason}" for c in csp.checks if c.allowed is None], \
            ["CSP uses 'strict-dynamic'; whether the widget loads depends on how it is injected."]
    if csp.verdict == "allows":
        return None, ["CSP present and allows the widget script and API origins."], []
    if csp.verdict == "report_only":
        return None, ["Only a Content-Security-Policy-Report-Only header is present (not enforced)."], []
    if csp.verdict == "not_checked":
        return None, ["CSP not checked: the response was a bot-protection page, not the real site."], []
    return None, ["No Content-Security-Policy restricts third-party scripts."], []


def _cap(f: Feasibility, cap: Feasibility | None) -> Feasibility:
    return f if cap is None or FEASIBILITY_RANK[f] >= FEASIBILITY_RANK[cap] else cap


SCRIPT_TAG_ROUTES = {
    Platform.SHOPIFY.value: ("Paste the snippet before </head> in layout/theme.liquid (Online Store > Themes > Edit code).",
                             ["Shopify staff permission to edit themes"],
                             ["Theme edits are lost when the merchant switches or replaces the theme."]),
    Platform.WOOCOMMERCE.value: ("Add the snippet to the site header with a header/footer-scripts plugin or a child theme.",
                                 ["WordPress Administrator (or theme file / plugin install access)"],
                                 ["Editing a parent theme's header.php is overwritten by theme updates; use a child theme or plugin."]),
    Platform.MAGENTO.value: ("Add the snippet in Admin > Content > Design > Configuration > HTML Head > Scripts and Style Sheets.",
                             ["Magento Admin role with Design configuration access"],
                             ["Full-page cache must be flushed after the change."]),
    Platform.BIGCOMMERCE.value: ("Add the snippet via Storefront > Script Manager (location: Footer, all pages).",
                                 ["BigCommerce store owner or staff with Script Manager permission"],
                                 ["Script Manager entries can be restricted by the store's script consent categories."]),
    Platform.WIX.value: ("Add the snippet in Settings > Custom Code (head, all pages).",
                         ["Wix site owner or admin role"],
                         ["Wix Custom Code requires a Premium plan and a connected custom domain."]),
}


def _script_tag(platform: str, signals: PageSignals, csp_cap, csp_ev, csp_risk, has_html: bool) -> InstallationOption:
    evidence, risks = list(csp_ev), list(csp_risk)
    if not has_html:
        return InstallationOption(method=InstallMethod.SCRIPT_TAG, feasibility=R,
                                  evidence=["Homepage HTML was not available to inspect."],
                                  client_action_required="Confirm how the site's HTML templates are managed.",
                                  permissions_required=["Access to edit site templates"], risks=risks)
    if signals.headless_commerce:
        evidence.append(f"Front end built with {signals.frontend_framework}; changes require a code deploy.")
        return InstallationOption(
            method=InstallMethod.SCRIPT_TAG, feasibility=_cap(P, csp_cap), evidence=evidence,
            client_action_required="A developer adds the script to the app's root layout and deploys it.",
            permissions_required=["Write access to the front-end codebase and its deployment pipeline"],
            risks=risks + ["Client-side route changes (SPA) must not re-initialise the widget on every navigation."])
    if platform in SCRIPT_TAG_ROUTES:
        action, perms, extra = SCRIPT_TAG_ROUTES[platform]
        feas = L
        if platform == Platform.WIX.value and signals.free_hosted_domain:
            feas = R
            evidence.append("Site is served from a free *.wixsite.com address: Custom Code is unavailable on free plans.")
        evidence.append(f"Platform {platform} provides a standard place to add site-wide scripts.")
        return InstallationOption(method=InstallMethod.SCRIPT_TAG, feasibility=_cap(feas, csp_cap), evidence=evidence,
                                  client_action_required=action, permissions_required=perms, risks=risks + extra)
    feas = P if platform == Platform.CUSTOM.value else R
    evidence.append("No known CMS: the snippet must go into the site's own templates." if platform == Platform.CUSTOM.value
                    else "Platform unknown: where templates are edited could not be determined.")
    return InstallationOption(method=InstallMethod.SCRIPT_TAG, feasibility=_cap(feas, csp_cap), evidence=evidence,
                              client_action_required="Whoever maintains the site adds the snippet to the shared page template.",
                              permissions_required=["Access to edit and deploy site templates"], risks=risks)


def _gtm(platform: str, signals: PageSignals, csp_cap, csp_ev, csp_risk) -> InstallationOption:
    evidence, risks = list(csp_ev), list(csp_risk)
    risks.append("GTM workspace policies (Custom HTML allowlists/blocklists) can prevent Custom HTML tags.")
    if signals.consent_managers:
        risks.append(f"Consent manager present ({', '.join(signals.consent_managers)}): the tag's trigger may need "
                     "a consent category, otherwise it may not fire for users who decline.")
    if platform == Platform.SHOPIFY.value:
        risks.append("If GTM runs inside a Shopify Customer Events (custom pixel) sandbox, it cannot inject the widget into the page.")
    if signals.gtm_containers:
        evidence.insert(0, f"GTM container(s) loaded on the homepage: {', '.join(signals.gtm_containers)}.")
        return InstallationOption(
            method=InstallMethod.GOOGLE_TAG_MANAGER, feasibility=_cap(L, csp_cap), evidence=evidence,
            client_action_required=f"Create a Custom HTML tag with the widget snippet in {signals.gtm_containers[0]}, "
                                   "trigger: All Pages (or Initialization), then Publish.",
            permissions_required=[f"Publish permission on GTM container {c}" for c in signals.gtm_containers],
            risks=risks)
    if signals.gtag_ids:
        evidence.insert(0, f"Only gtag.js found ({', '.join(signals.gtag_ids)}): a Google Analytics/Ads tag, "
                           "not a GTM container, so it cannot inject custom scripts.")
    else:
        evidence.insert(0, "No Google Tag Manager container found on the homepage.")
    return InstallationOption(
        method=InstallMethod.GOOGLE_TAG_MANAGER, feasibility=_cap(P, csp_cap), evidence=evidence,
        client_action_required="Install a GTM container on the site first (same access as a direct script), "
                               "then add the widget as a Custom HTML tag.",
        permissions_required=["Access to edit site templates (to add GTM)", "GTM container Publish permission"],
        risks=risks)


def _cms_app(platform: str, confidence: str, signals: PageSignals, csp_cap, csp_ev, csp_risk) -> InstallationOption:
    evidence, risks = list(csp_ev), list(csp_risk)
    m = InstallMethod.CMS_PLUGIN_APP
    if signals.headless_commerce:
        evidence.insert(0, f"Headless front end ({signals.frontend_framework}): theme-based app embeds and CMS plugins "
                           "do not render on a custom storefront.")
        return InstallationOption(method=m, feasibility=R, evidence=evidence,
                                  client_action_required="Use a code-level install (script tag / agency) instead.",
                                  permissions_required=[], risks=risks)
    strong = confidence in (Confidence.HIGH.value, Confidence.MEDIUM.value)
    if platform == Platform.SHOPIFY.value and strong:
        evidence.insert(0, f"Shopify storefront detected ({confidence} confidence); app embed blocks are supported by Shopify themes.")
        return InstallationOption(
            method=m, feasibility=_cap(L, csp_cap), evidence=evidence,
            client_action_required="Install our Shopify app, then turn on its app embed in Online Store > Themes > Customize > App embeds.",
            permissions_required=["Shopify store owner, or staff with 'Apps and channels' and 'Themes' permissions"],
            risks=risks + ["Requires our Shopify app to be available (App Store listing or custom distribution link).",
                           "App embeds render on the Online Store only, not on checkout or headless storefronts."])
    if platform == Platform.WOOCOMMERCE.value and strong:
        evidence.insert(0, f"WooCommerce on WordPress detected ({confidence} confidence).")
        r = risks + ["Some managed WordPress hosts restrict which plugins can be installed."]
        if signals.page_cache:
            r.append(f"Page cache detected ({'; '.join(signals.page_cache)}): purge it after activating the plugin.")
        return InstallationOption(
            method=m, feasibility=_cap(L, csp_cap), evidence=evidence,
            client_action_required="Install and activate our WordPress plugin (Plugins > Add New > Upload), then enter the API key.",
            permissions_required=["WordPress Administrator (install_plugins capability)"], risks=r)
    if platform in (Platform.WIX.value, Platform.BIGCOMMERCE.value) and strong:
        name = "Wix App Market" if platform == Platform.WIX.value else "BigCommerce App Marketplace"
        evidence.insert(0, f"{platform} detected ({confidence} confidence); platform supports third-party apps.")
        return InstallationOption(
            method=m, feasibility=_cap(P, csp_cap), evidence=evidence,
            client_action_required=f"Install our app from the {name} (requires our app to be published there).",
            permissions_required=[f"{platform} site/store owner or admin role"],
            risks=risks + [f"Depends on our app being available on the {name}."])
    if platform == Platform.MAGENTO.value and strong:
        evidence.insert(0, f"Magento / Adobe Commerce detected ({confidence} confidence).")
        return InstallationOption(
            method=m, feasibility=_cap(P, csp_cap), evidence=evidence,
            client_action_required="A developer installs our Magento module via Composer, runs setup:upgrade, and flushes caches.",
            permissions_required=["Server/SSH access and deploy rights for the Magento codebase"],
            risks=risks + ["Module installation needs a deployment window; compatibility depends on the Magento version."])
    evidence.insert(0, "No supported CMS/e-commerce platform detected with enough confidence for a plugin/app route.")
    return InstallationOption(method=m, feasibility=R, evidence=evidence,
                              client_action_required="None available until the platform is confirmed.",
                              permissions_required=[], risks=risks)


def _agency(platform: str, signals: PageSignals, csp: CSPAnalysis) -> InstallationOption:
    code_level = signals.headless_commerce or platform == Platform.CUSTOM.value
    evidence = []
    if code_level:
        evidence.append("Site appears custom-built or headless, so a code-level installation by its developers is the normal route.")
    else:
        evidence.append("Always available if the client works with a developer or agency.")
    action = "Send our installation package (snippet, integration docs"
    action += ", required CSP changes" if csp.verdict in ("blocks", "unclear") else ""
    action += ") to the developer/agency responsible for the site."
    return InstallationOption(
        method=InstallMethod.AGENCY_HANDOFF, feasibility=L if code_level else P, evidence=evidence,
        client_action_required=action,
        permissions_required=["Client authorisation for their developer/agency to make the change"],
        risks=["Timeline depends on the third party's release cycle.",
               "Ownership of future widget updates must be agreed with the agency."])


def _undetectable(platform: str, signals: PageSignals) -> list[str]:
    items = {
        Platform.SHOPIFY.value: "Whether the client is the Shopify store owner or a staff member with Apps/Themes permissions.",
        Platform.WOOCOMMERCE.value: "Whether the client has a WordPress Administrator account (needed to install plugins).",
        Platform.MAGENTO.value: "Whether the client has Magento Admin access and server/deploy access.",
        Platform.BIGCOMMERCE.value: "Whether the client is a BigCommerce store owner or has Script Manager/app permissions.",
        Platform.WIX.value: "Whether the client is the Wix site owner/admin and is on a Premium plan with a connected domain.",
    }
    out = [items.get(platform, "Who administers the site and through which system its templates are managed.")]
    if signals.gtm_containers:
        out.append(f"Whether the client has Publish rights on GTM container(s) {', '.join(signals.gtm_containers)}.")
    else:
        out.append("Whether the client uses a tag manager that is not loaded on the homepage.")
    out += [
        "Whether the client can edit theme/template code or deploy front-end changes.",
        "Whether the client (or their host/CDN) can change HTTP response headers such as Content-Security-Policy.",
        "Hosting or plan restrictions on installing plugins/apps or custom code.",
        "Internal approval processes for adding a new third-party vendor script (security/privacy review).",
    ]
    return out


# ======================================================================
# Entry point
# ======================================================================
def assess_widget_installation(
    home: FetchResult,
    platform_result: PlatformDetectionResult | None,
    discovery: SourceDiscoveryResult | None = None,
) -> WidgetAssessment:
    platform = platform_result.detected_platform.value if platform_result else Platform.UNKNOWN.value
    confidence = platform_result.confidence.value if platform_result else Confidence.LOW.value
    has_html = bool(home.html) and home.result.error_code != ErrorCode.BOT_PROTECTION

    if home.result.error_code == ErrorCode.BOT_PROTECTION:
        # A challenge page's headers belong to the WAF/CDN, not the store; using them would be a made-up finding.
        csp = CSPAnalysis(verdict="not_checked",
                          notes=["Homepage was a bot-protection challenge; the site's real CSP could not be observed."])
    else:
        csp = analyse_csp(home.headers or {}, home.html if has_html else "")
    signals = collect_signals(home, platform, discovery)
    csp_cap, csp_ev, csp_risk = _csp_effect(csp)

    common_risks = []
    if signals.existing_chat_widgets:
        common_risks.append(f"Existing chat widget(s) detected ({', '.join(signals.existing_chat_widgets)}): "
                            "agree placement to avoid overlapping launchers.")
    if signals.page_cache:
        common_risks.append(f"Pages are served from cache ({'; '.join(signals.page_cache)}): purge after installing.")
    csp_risk = csp_risk + common_risks

    options = [
        _cms_app(platform, confidence, signals, csp_cap, csp_ev, csp_risk),
        _gtm(platform, signals, csp_cap, csp_ev, csp_risk),
        _script_tag(platform, signals, csp_cap, csp_ev, csp_risk, has_html),
        _agency(platform, signals, csp),
    ]
    if not has_html:
        for opt in options[:2]:  # app/GTM verdicts depend on the homepage HTML
            opt.feasibility = R
            opt.evidence.insert(0, "Homepage HTML unavailable (blocked or not fetched); page-level signals could not be checked.")

    def selection_rank(o: InstallationOption) -> tuple[int, int]:
        rank = FEASIBILITY_RANK[o.feasibility]
        # "Install GTM first" is a detour, not a route: rank it below agency handoff.
        if o.method == InstallMethod.GOOGLE_TAG_MANAGER and not signals.gtm_containers:
            rank += 1
        return rank, METHOD_PREFERENCE.index(o.method)

    best = min(options, key=selection_rank)
    notes = []
    if WIDGET_SCRIPT_URL.endswith(".example/v1/widget.js") or ".example" in WIDGET_API_ORIGIN:
        notes.append("CSP was checked against placeholder widget URLs; set WIDGET_SCRIPT_URL / WIDGET_API_ORIGIN "
                     "to the production endpoints.")
    return WidgetAssessment(
        recommended_method=best.method if best.feasibility != R else InstallMethod.AGENCY_HANDOFF,
        options=options, csp=csp, signals=signals,
        undetectable_permissions=_undetectable(platform, signals), notes=notes,
    )
