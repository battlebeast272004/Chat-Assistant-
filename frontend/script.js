/*
 * Store Assessment dashboard.
 *
 * Flow: POST /api/assessment/start -> poll GET /api/assessment/{id} (real
 * progress from the server) -> render the report. History comes from
 * GET /api/assessment/history.
 *
 * SECURITY: reports contain text scraped from third-party sites. Everything
 * is rendered with textContent / createElement, never innerHTML. Links and
 * images only accept http(s) URLs. The server also sends a strict CSP.
 */
(() => {
  "use strict";

  const API = "/api/assessment";
  const POLL_INTERVAL_MS = 1000;
  const POLL_TIMEOUT_MS = 180000;
  const HISTORY_PAGE_SIZE = 10;

  // ------------------------------------------------------------------ labels
  const PLATFORM_LABELS = {
    shopify: "Shopify", woocommerce: "WooCommerce", wix: "Wix", magento: "Magento / Adobe Commerce",
    bigcommerce: "BigCommerce", custom: "Custom store", unknown: "Unknown platform",
  };
  const SOURCE_LABELS = {
    shopify_products_json: "Shopify products.json (public API)",
    shopify_storefront_api: "Shopify Storefront API",
    woocommerce_store_api: "WooCommerce Store API (public)",
    json_ld: "Schema.org JSON-LD",
    product_sitemap: "Product sitemap",
    html_product_pages: "Product pages (HTML)",
    sitemap: "Sitemap",
    xml_feed: "XML product feed",
  };
  const METHOD_LABELS = {
    cms_plugin_app: "Platform app / plugin",
    google_tag_manager: "Google Tag Manager",
    script_tag: "Script tag in theme / template",
    agency_handoff: "Developer / agency handoff",
  };
  const FEASIBILITY_LABELS = { likely: "Likely", possible: "Possible", requires_investigation: "Needs investigation" };
  const COMPAT_CLASS = {
    "Good candidate": "good", "Requires client access": "access", "Partially compatible": "partial",
    "Not currently supported": "unsupported", "Assessment incomplete": "incomplete",
  };
  const STEP_GROUPS = [
    { label: "Validating", steps: ["validation"] },
    { label: "Detecting platform", steps: ["platform_detection"] },
    { label: "Finding products", steps: ["source_discovery", "product_extraction"] },
    { label: "Evaluating compatibility", steps: ["widget_assessment", "compatibility"] },
  ];
  const ERROR_MESSAGES = {
    invalid_url: ["That URL isn't valid", "Use a full public address such as https://example-store.com."],
    unsafe_target: ["That address can't be assessed", "It points to a private, local or reserved network address."],
    dns_failure: ["Domain not found", "The domain name could not be resolved. Check the spelling."],
    timeout: ["The site took too long to respond", "It didn't finish responding within 10 seconds."],
    connection_error: ["Couldn't connect to the site", "The server refused or dropped the connection."],
    tls_error: ["Secure connection failed", "The site's HTTPS certificate could not be verified."],
    too_many_redirects: ["Too many redirects", "The site redirected more than 5 times."],
    redirect_loop: ["Redirect loop", "The site keeps redirecting back to itself."],
    response_too_large: ["Page too large", "The homepage is bigger than the 5 MB inspection limit."],
    http_error: ["The site returned an error", null],
    bot_protection: ["Blocked by bot protection", "The site served a security challenge instead of its pages. Results are limited to what was visible."],
  };
  const PRODUCT_FIELDS = ["description", "price", "currency", "category", "image_url", "product_url", "availability"];
  const FIELD_LABELS = {
    name: "Name", description: "Description", price: "Price", currency: "Currency", category: "Category",
    specifications: "Specs", image_url: "Image", product_url: "URL", availability: "Availability",
  };

  // ------------------------------------------------------------------ DOM helpers
  const $ = (sel) => document.querySelector(sel);

  /** Create an element. Text content is always set safely (never parsed as HTML). */
  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function append(parent, ...children) {
    for (const c of children) if (c) parent.append(c);
    return parent;
  }

  function isHttpUrl(value) {
    if (typeof value !== "string") return false;
    try { return ["http:", "https:"].includes(new URL(value).protocol); } catch { return false; }
  }

  function safeLink(url, text) {
    if (!isHttpUrl(url)) return el("span", "mono", text || url);
    const a = el("a", "mono", text || url);
    a.href = url;
    a.target = "_blank";
    a.rel = "noopener noreferrer nofollow";
    a.referrerPolicy = "no-referrer";
    return a;
  }

  function tag(text, kind, title) {
    const t = el("span", `tag tag-${kind}`, text);
    if (title) t.title = title;
    return t;
  }

  const verifiedTag = () => tag("✓ Verified", "verified", "Observed directly during this assessment");
  const confirmTag = () => tag("Client to confirm", "confirm", "Can't be detected publicly; confirm with the client");

  function domainOf(url) {
    try { return new URL(url).hostname; } catch { return url || "—"; }
  }

  function formatDate(iso) {
    if (!iso) return "—";
    const d = new Date(iso);
    return isNaN(d) ? "—" : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  }

  function formatPrice(price, currency) {
    if (price === null || price === undefined) return null;
    if (currency) {
      try { return new Intl.NumberFormat(undefined, { style: "currency", currency }).format(price); } catch { /* fall through */ }
    }
    return new Intl.NumberFormat(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 }).format(price);
  }

  function compatPill(status, extraClass = "") {
    const key = COMPAT_CLASS[status] || "incomplete";
    return el("span", `pill compat-${key} ${extraClass}`.trim(), status || "—");
  }

  function rowStatusPill(item) {
    if (item.status === "pending" || item.status === "running") return el("span", "pill compat-running", "Running…");
    if (item.compatibility_status) return compatPill(item.compatibility_status);
    return el("span", "pill compat-failed", item.status === "failed" ? "Failed" : item.status);
  }

  // ------------------------------------------------------------------ API
  class ApiError extends Error {
    constructor(status, body) {
      super(body && (body.error || body.detail) ? (body.error || body.detail) : `HTTP ${status}`);
      this.status = status;
      this.body = body || {};
    }
  }

  async function api(path, options = {}) {
    let res;
    try {
      res = await fetch(path, { headers: { "Content-Type": "application/json" }, cache: "no-store", ...options });
    } catch {
      throw new ApiError(0, { error: "Could not reach the assessment server. Is it running?" });
    }
    let body = null;
    try { body = await res.json(); } catch { /* non-JSON */ }
    if (!res.ok) throw new ApiError(res.status, body);
    return body;
  }

  // ------------------------------------------------------------------ banners
  function clearBanners() { $("#banners").replaceChildren(); }

  function showBanner(kind, title, message) {
    const icon = { error: "!", warning: "!", info: "i" }[kind];
    const b = el("div", `banner banner-${kind}`);
    b.setAttribute("role", kind === "error" ? "alert" : "status");
    const body = el("div", "banner-body");
    append(body, el("div", "banner-title", title), message ? el("p", null, message) : null);
    const close = el("button", "close", "✕");
    close.setAttribute("aria-label", "Dismiss");
    close.addEventListener("click", () => b.remove());
    append(b, el("span", "banner-icon", icon), body, close);
    $("#banners").append(b);
  }

  function bannerForErrorCode(code, fallbackMessage, httpStatus) {
    const [title, msg] = ERROR_MESSAGES[code] || ["Assessment problem", null];
    const detail = code === "http_error" && httpStatus
      ? `The homepage responded with HTTP ${httpStatus}, so the assessment only covers what was returned.`
      : msg || fallbackMessage;
    return [title, detail];
  }

  // ------------------------------------------------------------------ navigation
  const TITLES = { dashboard: "Dashboard", new: "New Assessment", history: "Assessment History", settings: "Settings" };

  function showView(name) {
    const viewId = name === "new" ? "dashboard" : name;
    document.querySelectorAll(".view").forEach((v) => { v.hidden = v.id !== `view-${viewId}`; });
    document.querySelectorAll(".nav-item").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
    $("#page-title").textContent = TITLES[name] || "Dashboard";
    closeSidebar();
    if (name === "new") { $("#url-input").focus(); window.scrollTo({ top: 0, behavior: "smooth" }); }
    if (name === "history") loadHistory(historyPage);
  }

  function closeSidebar() { $("#sidebar").classList.remove("open"); $("#scrim").hidden = true; }

  document.querySelectorAll(".nav-item").forEach((b) => b.addEventListener("click", () => showView(b.dataset.view)));
  document.querySelectorAll("[data-goto]").forEach((b) => b.addEventListener("click", () => showView(b.dataset.goto)));
  $("#menu-btn").addEventListener("click", () => {
    const open = $("#sidebar").classList.toggle("open");
    $("#scrim").hidden = !open;
  });
  $("#scrim").addEventListener("click", closeSidebar);

  // ------------------------------------------------------------------ form + progress
  let activePoll = null;

  function validateUrl(raw) {
    let value = raw.trim();
    if (!value) return { error: "Enter a store URL to analyse." };
    if (value.length > 2048) return { error: "That URL is too long (max 2048 characters)." };
    if (/\s/.test(value)) return { error: "URLs can't contain spaces." };
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) value = `https://${value}`;
    let u;
    try { u = new URL(value); } catch { return { error: "That doesn't look like a valid URL." }; }
    if (!["http:", "https:"].includes(u.protocol)) return { error: "Only http:// and https:// addresses can be assessed." };
    if (u.username || u.password) return { error: "Remove the username/password from the URL." };
    if (!u.hostname.includes(".")) return { error: "Enter a full domain, e.g. example-store.com." };
    return { url: value };
  }

  function setBusy(busy) {
    const btn = $("#analyse-btn");
    btn.disabled = busy;
    btn.classList.toggle("loading", busy);
    btn.querySelector(".btn-label").textContent = busy ? "Analysing…" : "Analyse Website";
    $("#url-input").disabled = busy;
  }

  function renderStepper(currentStep, finished) {
    const activeIdx = finished ? STEP_GROUPS.length
      : Math.max(0, STEP_GROUPS.findIndex((g) => g.steps.includes(currentStep)));
    $("#stepper").replaceChildren(...STEP_GROUPS.map((g, i) => {
      const state = i < activeIdx ? "done" : i === activeIdx ? "active" : "pending";
      const li = el("li", `step ${state}`);
      li.setAttribute("aria-current", state === "active" ? "step" : "false");
      append(li, el("span", "step-marker", state === "done" ? "✓" : String(i + 1)), el("span", null, g.label));
      return li;
    }));
  }

  function showProgress(domain) {
    $("#progress-domain").textContent = domain;
    $("#progress-hint").textContent = "This usually takes 5–30 seconds.";
    renderStepper(null, false);
    $("#progress-card").hidden = false;
    $("#results").hidden = true;
  }

  function stopPolling() {
    if (activePoll) { clearTimeout(activePoll.timer); activePoll = null; }
  }

  function pollAssessment(id, domain) {
    stopPolling();
    showProgress(domain);
    setBusy(true);
    const started = Date.now();
    const poll = { timer: null };
    activePoll = poll;

    const tick = async () => {
      if (activePoll !== poll) return;
      try {
        const rec = await api(`${API}/${id}`);
        if (activePoll !== poll) return;
        if (rec.status === "pending" || rec.status === "running") {
          renderStepper(rec.current_step, false);
          if (Date.now() - started > 30000) $("#progress-hint").textContent = "Still working: some sites respond slowly.";
          if (Date.now() - started > POLL_TIMEOUT_MS) throw new ApiError(408, { error: "The assessment is taking unusually long. Check History later." });
          poll.timer = setTimeout(tick, POLL_INTERVAL_MS);
          return;
        }
        renderStepper(null, true);
        finish();
        renderRecord(rec);
        loadHistory(1);
      } catch (err) {
        if (activePoll !== poll) return;
        finish();
        $("#progress-card").hidden = true;
        showBanner("error", "Couldn't get the assessment result", err.message);
      }
    };
    const finish = () => { stopPolling(); setBusy(false); };
    tick();
  }

  $("#assess-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    clearBanners();
    const { url, error } = validateUrl($("#url-input").value);
    if (error) { showBanner("error", "Check the URL", error); $("#url-input").focus(); return; }

    setBusy(true);
    try {
      const res = await api(`${API}/start`, { method: "POST", body: JSON.stringify({ url }) });
      history.replaceState(null, "", `#assessment/${res.id}`);
      pollAssessment(res.id, domainOf(res.normalized_url));
      loadHistory(1);
    } catch (err) {
      setBusy(false);
      if (err.status === 400) {
        const [title, msg] = bannerForErrorCode(err.body.error_code, err.body.error);
        showBanner("error", title, msg);
      } else if (err.status === 429) {
        showBanner("warning", "Slow down", err.message);
      } else if (err.status === 422) {
        showBanner("error", "Check the URL", "The server could not read that URL.");
      } else {
        showBanner("error", "Couldn't start the assessment", err.message);
      }
    }
  });

  // ------------------------------------------------------------------ results rendering
  function renderRecord(rec) {
    clearBanners();
    $("#progress-card").hidden = true;
    const report = rec.report;
    if (!report) {
      showBanner("error", "This assessment has no report", rec.error_message || "It failed before a report was produced.");
      $("#results").hidden = true;
      return;
    }
    const t = report.target || {};
    if (t.error_code) {
      const [title, msg] = bannerForErrorCode(t.error_code, t.error, t.http_status);
      showBanner(t.error_code === "bot_protection" || t.error_code === "http_error" ? "warning" : "error", title, msg);
    }
    if (report.compatibility && report.compatibility.status === "Assessment incomplete" && !t.error_code) {
      showBanner("warning", "Assessment incomplete", (report.compatibility.reasons || [])[0]);
    }

    const root = $("#results");
    root.replaceChildren(
      renderHeader(rec, report),
      append(el("div", "two-col"), renderSources(report), renderWidget(report)),
      renderProducts(report),
      renderRawJson(report),
    );
    root.hidden = false;
    root.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function renderHeader(rec, report) {
    const card = el("article", "card");
    const t = report.target || {};
    const domain = domainOf(t.final_url || t.normalized_url || report.input_url);
    const p = report.platform;

    const title = el("div", "result-title");
    const badges = el("div", "result-badges");
    const badge = el("span", "platform-badge", p ? (PLATFORM_LABELS[p.detected_platform] || p.detected_platform) : "Platform not detected");
    if (p) badge.append(el("span", "conf", `· ${p.confidence} confidence`));
    append(badges, badge, compatPill(report.compatibility.status, "pill-lg"));
    append(title, el("h2", null, domain), t.page_title ? el("p", "muted", t.page_title) : null, badges,
      el("p", "muted small", `Assessment #${rec.id} · ${formatDate(report.generated_at)} · took ${(report.duration_ms / 1000).toFixed(1)} s`
        + (t.http_status ? ` · HTTP ${t.http_status}` : "")));

    const actions = el("div", "result-actions");
    const close = el("button", "btn btn-ghost", "✕");
    close.setAttribute("aria-label", "Close results");
    close.addEventListener("click", () => { $("#results").hidden = true; clearBanners(); history.replaceState(null, "", "#"); });
    actions.append(close);

    const head = append(el("div", "result-header"), title, actions);

    const grid = el("div", "reason-grid");
    const reasons = el("div");
    append(reasons, el("h4", null, `Why: rule ${report.compatibility.rule}`),
      append(el("ul", "plain-list"), ...(report.compatibility.reasons || []).map((r) => el("li", null, r))));
    const next = el("div");
    append(next, el("h4", null, "Next steps"),
      append(el("ul", "plain-list"), ...(report.compatibility.next_steps || []).map((r) => el("li", null, r))));
    append(grid, reasons, next);

    const steps = el("div", "step-chips");
    for (const s of report.steps || []) {
      const kind = { completed: "verified", partial: "confirm", skipped: "muted", failed: "blocked" }[s.status] || "muted";
      steps.append(tag(`${s.name.replace(/_/g, " ")}: ${s.status}`, kind, s.detail || ""));
    }
    return append(card, head, grid, steps);
  }

  function legend() {
    return append(el("div", "legend"), verifiedTag(), el("span", null, "observed during this assessment"),
      confirmTag(), el("span", null, "can't be detected publicly"));
  }

  function renderSources(report) {
    const card = el("article", "card");
    const discovery = report.product_data && report.product_data.discovery;
    append(card, append(el("div", "card-head stacked"), el("h3", null, "Product data sources"), legend()));
    if (!discovery || !discovery.sources || !discovery.sources.length) {
      card.append(el("p", "muted", discovery ? "No product data sources were found." : "Source discovery did not run."));
      return card;
    }
    const list = el("ul", "item-list");
    for (const s of discovery.sources) {
      const li = el("li", "item");
      const head = el("div", "item-head");
      const name = el("span", "item-name", SOURCE_LABELS[s.source_type] || s.source_type);
      const tags = el("span", "signal-chips");
      if (s.source_type === discovery.recommended_source && s.accessible) tags.append(tag("Recommended", "recommended"));
      if (s.accessible) tags.append(verifiedTag());
      else if (s.requires_auth) tags.append(tag("Needs client credentials", "confirm"));
      else if (s.http_status && s.http_status !== 200) tags.append(tag(`Not available (HTTP ${s.http_status})`, "muted"));
      else tags.append(tag("Not found", "muted", "Checked, but no usable product data was present"));
      append(head, name, tags);
      li.append(head, safeLink(s.source_url));
      if (s.evidence) li.append(el("span", "small", s.evidence));
      if (s.limitations && s.limitations.length) {
        const d = el("details", "more");
        d.append(el("summary", null, `${s.limitations.length} limitation(s)`),
          append(el("ul", "plain-list small"), ...s.limitations.map((l) => el("li", null, l))));
        li.append(d);
      }
      list.append(li);
    }
    card.append(list);
    if (discovery.notes && discovery.notes.length) {
      const d = el("details", "more");
      d.append(el("summary", null, "Discovery notes"), append(el("ul", "plain-list small"), ...discovery.notes.map((n) => el("li", null, n))));
      card.append(d);
    }
    return card;
  }

  function renderWidget(report) {
    const card = el("article", "card");
    const w = report.widget;
    append(card, append(el("div", "card-head stacked"), el("h3", null, "Widget installation"), legend()));
    if (!w) { card.append(el("p", "muted", "Widget assessment did not run.")); return card; }

    // Verified page signals
    const sig = w.signals || {};
    const facts = el("ul", "fact-list");
    const cspText = {
      no_csp: "No Content-Security-Policy restricts third-party scripts.",
      allows: "Content-Security-Policy allows the widget script and API.",
      blocks: "Content-Security-Policy blocks the widget; the client must update it.",
      unclear: "Content-Security-Policy uses 'strict-dynamic'; needs manual verification.",
      report_only: "Only a report-only CSP is present (not enforced).",
      not_checked: "CSP not checked: the site served a bot-protection page.",
    }[w.csp.verdict] || `CSP: ${w.csp.verdict}`;
    const fact = (text, t = verifiedTag()) => append(el("li"), t, el("span", null, text));
    facts.append(fact(cspText, w.csp.verdict === "blocks" ? tag("✓ Verified · blocker", "blocked") : verifiedTag()));
    if (sig.gtm_containers && sig.gtm_containers.length) facts.append(fact(`GTM container: ${sig.gtm_containers.join(", ")}`));
    if (sig.frontend_framework) facts.append(fact(`Front end: ${sig.frontend_framework}${sig.headless_commerce ? " (headless)" : ""}`));
    if (sig.existing_chat_widgets && sig.existing_chat_widgets.length) facts.append(fact(`Existing chat: ${sig.existing_chat_widgets.join(", ")}`));
    if (sig.consent_managers && sig.consent_managers.length) facts.append(fact(`Consent manager: ${sig.consent_managers.join(", ")}`));
    if (sig.page_cache && sig.page_cache.length) facts.append(fact(`Page cache: ${sig.page_cache.join("; ")}`));
    card.append(facts);

    const list = el("ul", "item-list");
    list.style.marginTop = "14px";
    for (const o of w.options) {
      const rec = o.method === w.recommended_method;
      const li = el("li", `item option${rec ? " recommended" : ""}`);
      const tags = el("span", "signal-chips");
      if (rec) tags.append(tag("Recommended", "recommended"));
      tags.append(tag(FEASIBILITY_LABELS[o.feasibility] || o.feasibility, o.feasibility));
      li.append(append(el("div", "item-head"), el("span", "item-name", METHOD_LABELS[o.method] || o.method), tags));
      li.append(el("div", "option-action", o.client_action_required));

      const ev = el("ul", "fact-list");
      o.evidence.forEach((e) => ev.append(fact(e)));
      o.permissions_required.forEach((p) => ev.append(fact(p, confirmTag())));
      li.append(ev);
      if (o.risks.length) {
        const d = el("details", "more");
        d.append(el("summary", null, `${o.risks.length} risk(s)`), append(el("ul", "plain-list small"), ...o.risks.map((r) => el("li", null, r))));
        li.append(d);
      }
      list.append(li);
    }
    card.append(list);

    if (w.undetectable_permissions && w.undetectable_permissions.length) {
      const box = el("div");
      box.style.marginTop = "14px";
      append(box, el("div", "section-label", "Confirm with the client"),
        append(el("ul", "fact-list"), ...w.undetectable_permissions.map((p) => fact(p, confirmTag()))));
      card.append(box);
    }
    if (w.notes && w.notes.length) card.append(append(el("ul", "plain-list small muted"), ...w.notes.map((n) => el("li", null, n))));
    return card;
  }

  function renderProducts(report) {
    const card = el("article", "card");
    const ex = report.product_data && report.product_data.extraction;
    const head = el("div", "card-head");
    const h = el("div");
    append(h, el("h3", null, "Extracted products"),
      el("p", "muted small", ex && ex.source_type
        ? `${ex.items_extracted} sample(s) from ${SOURCE_LABELS[ex.source_type] || ex.source_type}. Missing values are shown as missing, never estimated.`
        : "No products were extracted."));
    head.append(h);
    card.append(head);
    if (!ex) return card;

    if (ex.items_extracted) {
      const cov = el("div", "coverage");
      for (const [field, pct] of Object.entries(ex.field_coverage || {})) {
        const row = el("div", "cov-row");
        const bar = el("div", "cov-bar");
        const fill = el("div", `cov-fill${pct < 50 ? " low" : pct < 100 ? " mid" : ""}`);
        fill.style.width = `${Math.max(0, Math.min(100, pct))}%`;
        bar.append(fill);
        append(row, append(el("div", "cov-label"), el("span", null, FIELD_LABELS[field] || field), el("span", null, `${pct}%`)), bar);
        cov.append(row);
      }
      card.append(cov);
      const grid = el("div", "products");
      ex.products.slice(0, 5).forEach((p) => grid.append(productCard(p)));
      card.append(grid);
    }
    const notes = [...(ex.warnings || [])];
    if (notes.length) card.append(append(el("ul", "plain-list small muted"), ...notes.map((n) => el("li", null, n))));
    return card;
  }

  function productCard(p) {
    const card = el("div", "product");
    const imgBox = el("div", "product-img");
    if (isHttpUrl(p.image_url)) {
      const img = document.createElement("img");
      img.src = p.image_url;
      img.alt = p.name;
      img.loading = "lazy";
      img.referrerPolicy = "no-referrer";
      img.addEventListener("error", () => imgBox.replaceChildren(el("span", null, "Image unavailable")));
      imgBox.append(img);
    } else {
      imgBox.append(el("span", null, "No image"));
    }
    const body = el("div", "product-body");
    const name = isHttpUrl(p.product_url) ? safeLink(p.product_url, p.name) : el("span", null, p.name);
    name.classList.add("product-name");
    name.classList.remove("mono");
    const price = el("div", "product-price");
    const formatted = formatPrice(p.price, p.currency);
    if (formatted) {
      price.textContent = formatted;
      if (!p.currency) price.append(el("span", "null", " (currency not stated)"));
    } else {
      price.append(el("span", "null", "Price not available"));
    }
    append(body, name, price);
    if (p.availability) body.append(tag(p.availability.replace(/([a-z])([A-Z])/g, "$1 $2"),
      p.availability === "InStock" ? "verified" : "muted"));

    const missing = PRODUCT_FIELDS.filter((f) => p[f] === null || p[f] === undefined || p[f] === "");
    if (!p.specifications || !Object.keys(p.specifications).length) missing.push("specifications");
    if (missing.length) {
      const m = el("div", "missing");
      missing.forEach((f) => m.append(tag(`Missing ${FIELD_LABELS[f].toLowerCase()}`, "confirm")));
      body.append(m);
    }
    card.append(imgBox, body);
    return card;
  }

  function renderRawJson(report) {
    const d = el("details", "card raw-json");
    d.append(el("summary", null, "Raw JSON report"));
    d.addEventListener("toggle", () => {
      if (d.open && !d.querySelector("pre")) d.append(el("pre", null, JSON.stringify(report, null, 2)));
    });
    return d;
  }

  // ------------------------------------------------------------------ history
  let historyPage = 1;
  let historyItems = [];

  function historyRow(item) {
    const tr = el("tr", "clickable");
    tr.tabIndex = 0;
    const platformTd = el("td");
    platformTd.append(item.platform ? document.createTextNode(PLATFORM_LABELS[item.platform] || item.platform) : el("span", "null", "—"));
    const statusTd = el("td");
    statusTd.append(rowStatusPill(item));
    const act = el("td", "cell-actions");
    act.append(el("button", "btn btn-sm", "View"));
    append(tr, el("td", "cell-url", item.domain || item.url), platformTd, statusTd, el("td", null, formatDate(item.created_at)), act);
    const open = () => openAssessment(item.id);
    tr.addEventListener("click", open);
    tr.addEventListener("keydown", (e) => { if (e.key === "Enter") open(); });
    return tr;
  }

  function renderStats(data) {
    const s = data.summary || {};
    const tiles = [
      ["Total assessments", data.total],
      ["Good candidates", s["Good candidate"] || 0],
      ["Need client access / partial", (s["Requires client access"] || 0) + (s["Partially compatible"] || 0)],
      ["Unsupported / incomplete", (s["Not currently supported"] || 0) + (s["Assessment incomplete"] || 0)],
    ];
    $("#stats").replaceChildren(...tiles.map(([label, value]) =>
      append(el("div", "stat"), el("div", "stat-label", label), el("div", "stat-value", value))));
  }

  function renderSidebarRecent(items) {
    const list = $("#sidebar-recent");
    if (!items.length) { list.replaceChildren(el("li", "muted small", "No assessments yet")); return; }
    list.replaceChildren(...items.slice(0, 6).map((item) => {
      const li = el("li");
      const b = el("button");
      const dotClass = item.status === "running" || item.status === "pending" ? "running"
        : COMPAT_CLASS[item.compatibility_status] || "incomplete";
      b.title = `${item.domain || item.url}: ${item.compatibility_status || item.status}`;
      append(b, el("span", `dot dot-${dotClass}`), el("span", "domain", item.domain || item.url));
      b.addEventListener("click", () => openAssessment(item.id));
      li.append(b);
      return li;
    }));
  }

  function applyHistoryFilter() {
    const q = $("#history-search").value.trim().toLowerCase();
    const rows = historyItems.filter((i) => !q || [i.domain, i.url, i.platform, i.compatibility_status, i.status]
      .some((v) => (v || "").toLowerCase().includes(q)));
    $("#history-body").replaceChildren(...rows.map(historyRow));
    $("#history-empty").hidden = rows.length > 0;
  }

  async function loadHistory(page = 1) {
    try {
      const data = await api(`${API}/history?page=${encodeURIComponent(page)}&page_size=${HISTORY_PAGE_SIZE}`);
      const pages = Math.max(1, Math.ceil(data.total / data.page_size));
      if (page > pages && page > 1) return loadHistory(pages);
      historyPage = data.page;
      historyItems = data.items;
      applyHistoryFilter();
      $("#page-info").textContent = `Page ${data.page} of ${pages} · ${data.total} total`;
      $("#prev-page").disabled = data.page <= 1;
      $("#next-page").disabled = data.page >= pages;
      if (data.page === 1) {
        $("#recent-body").replaceChildren(...data.items.slice(0, 5).map(historyRow));
        $("#recent-empty").hidden = data.items.length > 0;
        renderSidebarRecent(data.items);
        renderStats(data);
      }
    } catch (err) {
      $("#recent-empty").hidden = false;
      $("#recent-empty").textContent = `Couldn't load history: ${err.message}`;
    }
  }

  $("#history-search").addEventListener("input", applyHistoryFilter);
  $("#prev-page").addEventListener("click", () => loadHistory(historyPage - 1));
  $("#next-page").addEventListener("click", () => loadHistory(historyPage + 1));

  async function openAssessment(id) {
    showView("dashboard");
    clearBanners();
    history.replaceState(null, "", `#assessment/${id}`);
    try {
      const rec = await api(`${API}/${encodeURIComponent(id)}`);
      if (rec.status === "pending" || rec.status === "running") {
        pollAssessment(rec.id, rec.domain || rec.url);
      } else {
        stopPolling();
        setBusy(false);
        renderRecord(rec);
      }
    } catch (err) {
      showBanner("error", err.status === 404 ? "Assessment not found" : "Couldn't load the assessment", err.message);
    }
  }

  // ------------------------------------------------------------------ health + init
  async function checkHealth() {
    const dot = $("#api-dot");
    const label = $("#api-status");
    try {
      const body = await api("/health");
      const ok = body && body.status === "healthy";
      dot.className = `status-dot ${ok ? "ok" : "down"}`;
      label.textContent = ok ? "API healthy" : "API unhealthy";
    } catch {
      dot.className = "status-dot down";
      label.textContent = "API unreachable";
    }
  }

  function openFromHash() {
    const m = /^#assessment\/(\d{1,18})$/.exec(location.hash);
    if (m) openAssessment(m[1]);
  }

  window.addEventListener("hashchange", openFromHash);
  checkHealth();
  setInterval(checkHealth, 30000);
  loadHistory(1).then(openFromHash);
})();
