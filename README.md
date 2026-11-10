# Website Assessment Module

Checks an e-commerce store before onboarding it to the AI Shopping Assistant. Given a store URL, it reports:

- the store's **platform** (Shopify, WooCommerce, Wix, Magento, BigCommerce, Custom or Unknown), with evidence for the decision
- where **product data** can be read from (public APIs, JSON-LD, sitemaps, product pages, feeds)
- up to **5 sample products** in one normalized schema
- the **widget installation** options (app/plugin, Google Tag Manager, script tag, agency handoff), including the site's Content-Security-Policy
- an overall **compatibility status**, plus the rule that produced it

Every assessment is saved in SQLite and can be opened again from the dashboard.

**Rules this project follows:** results are deterministic (no LLM), missing data is never made up (it stays `null`), outbound requests are SSRF-safe and capped at 10 s / 5 MB, and the output is versioned JSON (`report_schema_version: "1.0"`).

---

## Running the application locally

Requirements: **Python 3.11+** (developed on 3.12) and a modern browser.

### 1. Get the code and open a terminal in the project folder
```powershell
cd "C:\Users\DELL\Desktop\Chat Bot\Web Assessment Module"
```

### 2. Create and activate a virtual environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```
If PowerShell blocks the script, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once.
On macOS/Linux use `python3 -m venv .venv` and `source .venv/bin/activate`.

### 3. Install dependencies
```powershell
python -m pip install --upgrade pip
pip install -r backend\requirements.txt        # app
pip install -r backend\requirements-dev.txt    # + pytest/httpx for the tests (optional)
```

### 4. (Optional) configure
```powershell
copy .env.example .env      # then edit .env, e.g. set WIDGET_SCRIPT_URL / WIDGET_API_ORIGIN
```

### 5. Start the server (from `backend/`)
```powershell
cd backend
uvicorn main:app --reload --host 127.0.0.1 --port 8000
# with your .env:
uvicorn main:app --reload --host 127.0.0.1 --port 8000 --env-file ..\.env
```
On startup the log shows `Database ready at ...\data\assessments.db (journal_mode=wal)`. The database file is created automatically.

### 6. Use it
- **Dashboard:** http://127.0.0.1:8000. Enter a store URL and click **Analyse Website**. The progress steps (Validating, Detecting platform, Finding products, Evaluating compatibility) follow the server's actual progress. Past assessments appear in the sidebar, under **Recent assessments**, and in **Assessment History**; click one to reopen its report. Reports have shareable links (`/#assessment/<id>`).
- **API docs:** http://127.0.0.1:8000/docs

### 7. Check it from the command line
```powershell
Invoke-RestMethod http://127.0.0.1:8000/health                       # -> status: healthy
Invoke-RestMethod -Method Post http://127.0.0.1:8000/api/assessment/analyse -ContentType "application/json" -Body '{"url":"https://www.allbirds.com"}' | ConvertTo-Json -Depth 10
Invoke-RestMethod "http://127.0.0.1:8000/api/assessment/history?page=1&page_size=10"
```
bash / Git Bash:
```bash
curl -s http://127.0.0.1:8000/health
curl -s -X POST http://127.0.0.1:8000/api/assessment/analyse -H "Content-Type: application/json" -d '{"url":"https://www.allbirds.com"}'
curl -s "http://127.0.0.1:8000/api/assessment/history?page=1&page_size=10"
```
In Windows PowerShell 5.1, `curl` is an alias for `Invoke-WebRequest`, and `curl.exe` removes the inner quotes from JSON bodies. Use `Invoke-RestMethod` there.

### 8. Run the tests
```powershell
cd backend
python -m pytest -q
```
There are about 305 tests. DNS and HTTP are replaced with fakes, so the tests never touch the network, and each test gets its own temporary SQLite file.

Good public stores to try: `https://www.allbirds.com` (Shopify), `https://scrapeme.live/shop/` (WooCommerce demo), `https://www.gymshark.com` (headless storefront), `https://webscraper.io/test-sites/e-commerce/allinone` (custom test shop with no structured data).

---

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Checks the server is running |
| POST | `/api/assessment/start` | `{"url"}`. Validates the URL immediately (**400** with `error_code` if invalid or unsafe), then runs the assessment in the background. Returns **202** `{id}` |
| GET | `/api/assessment/{id}` | Status and `current_step` while running; the full `report` when finished. **404** if not found |
| GET | `/api/assessment/history?page=&page_size=` | Saved assessments, newest first (max 100 per page), plus `total` and a `summary` count by status |
| POST | `/api/assessment/analyse` | Synchronous full assessment. Returns the report and saves it (row id in the `X-Assessment-Id` header) |
| POST | `/api/assessment/validate` | Stage 2 only: URL validation and accessibility check |
| POST | `/api/assessment/detect-platform` | Stage 2 only: platform detection |
| POST | `/api/assessment/detect-sources` | Stage 3 only: product data source discovery |
| POST | `/api/assessment/extract-products` | Stage 3 only: discovery plus up to 5 normalized products |

A real report (trimmed) is in [docs/sample-report.json](docs/sample-report.json).

### Compatibility statuses
The status comes from an ordered rule table in `services/assessment_engine.py`. The rule that fired is in `compatibility.rule`.

| Status | Typical cause |
|---|---|
| Good candidate | Products extracted with good coverage, and a self-serve install route (app/plugin or existing GTM) is likely with no CSP blocker |
| Requires client access | Products are fine but installation needs theme/code/CSP access, or product data needs API credentials |
| Partially compatible | Weak product data (price coverage < 80%), or no install route could be confirmed |
| Not currently supported | No structured product data from any public source |
| Assessment incomplete | URL unreachable, bot protection or the time budget prevented the check, or an internal step failed |

`target.error_code` values: `invalid_url`, `unsafe_target`, `dns_failure`, `timeout`, `connection_error`, `tls_error`, `too_many_redirects`, `redirect_loop`, `response_too_large`, `http_error`, `bot_protection`.

---

## Project layout
```
backend/
  main.py                    FastAPI app: routes, static files, security headers, startup
  database/connection.py     SQLite (WAL) helpers: create/progress/save/list/get (parameterized SQL)
  database/models.py         assessments table schema + migration columns
  models/                    Pydantic contracts: product, source, widget, report
  routes/assessment.py       API endpoints (rate limited)
  services/
    url_validator.py         SSRF-safe fetcher; the ONLY module that makes HTTP requests
    platform_detector.py     weighted, evidence-based platform detection
    source_detector.py       product data source discovery (APIs, JSON-LD, robots/sitemaps, feeds)
    structured_data.py       tolerant JSON-LD/OpenGraph parsing and strict normalization
    product_extractor.py     sample extraction by priority, with fallback
    widget_checker.py        install routes, CSP analysis, page signals
    assessment_engine.py     orchestrator, error boundaries, compatibility rules
    jobs.py                  background job runner + report persistence
    rate_limit.py            per-IP sliding-window limiter
  tests/                     pytest suite (offline)
frontend/                    index.html, style.css, script.js, favicon.svg (vanilla, no build step)
docs/sample-report.json      example output
data/                        runtime SQLite database (git-ignored)
```

## Security and stability
- **SSRF protection.** Only http/https on ports 80/443/8080/8443 are allowed. Every resolved IP must be public, and the socket connects to the IP that was checked (which defeats DNS rebinding). Each redirect hop is re-validated, and URLs found in robots.txt, sitemaps and pages go through the same checks.
- **Limits.** 10 s wall-clock per request (covering the whole redirect chain), 5 MB of *decompressed* body, 5 redirects, a 30 s (+20 s) budget per assessment, and XML parsed with `defusedxml`. Callers can only lower these limits, and a test enforces that.
- **Database.** All SQL uses `?` placeholders, and a test fails the build if user data is ever formatted into SQL.
- **Dashboard.** All scraped text is rendered with `textContent` (never `innerHTML`). The server sends a strict CSP (`script-src 'self'`, no inline code), `nosniff` and `frame-ancestors 'none'`. Images load with `no-referrer`, and links only accept http(s).
- **Abuse limits.** 10 assessments per minute per IP, at most 3 running jobs and 20 queued (HTTP 429 beyond that). Jobs that were running during a restart are marked failed at startup.
- **Not included.** There is no authentication. Put this behind your SSO or a reverse proxy before exposing it outside a trusted network.

## Configuration
Set these as environment variables or in `.env` (see `.env.example`).

| Env var | Default | Purpose |
|---|---|---|
| `ASSESSMENT_DB_PATH` | `data/assessments.db` | SQLite file location |
| `WIDGET_SCRIPT_URL` | placeholder | Widget script URL tested against each store's CSP `script-src` |
| `WIDGET_API_ORIGIN` | placeholder | Widget API origin tested against `connect-src` |
| `WIDGET_FRAME_ORIGIN` | *(empty)* | Set if the widget uses an iframe (`frame-src`) |
| `ASSESSMENTS_PER_MINUTE` | `10` | Per-IP rate limit (`0` disables it) |
| `MAX_CONCURRENT_JOBS` / `MAX_QUEUED_JOBS` | `3` / `20` | Background worker pool limits |
