"""FastAPI entry point.

Run from the `backend/` directory:
    uvicorn main:app --reload
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from database.connection import DB_PATH, fail_interrupted_assessments, get_journal_mode, init_db
from routes import assessment, health

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(name)s: %(message)s")
logger = logging.getLogger("assessment")

# Resolve paths relative to this file, NOT the current working directory,
# so the app works no matter where uvicorn is launched from.
BACKEND_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BACKEND_DIR.parent / "frontend"

# The dashboard shows data scraped from third-party sites. A strict CSP is a
# second line of defence behind the frontend's textContent-only rendering.
# img-src allows https: because product images are hot-linked.
DASHBOARD_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' https: data:; "
    "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    interrupted = fail_interrupted_assessments()
    if interrupted:
        logger.warning("Marked %d interrupted assessment(s) as failed", interrupted)
    logger.info("Database ready at %s (journal_mode=%s)", DB_PATH, get_journal_mode())
    yield


app = FastAPI(
    title="Website Assessment Module",
    version="0.5.0",
    description="Deterministic e-commerce compatibility assessment for the AI shopping assistant widget.",
    lifespan=lifespan,
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    # Swagger UI (/docs) loads its assets from a CDN, so it's exempt from the dashboard CSP.
    if not request.url.path.startswith(("/docs", "/redoc", "/openapi.json")):
        response.headers.setdefault("Content-Security-Policy", DASHBOARD_CSP)
    return response


# --- API routes (registered before static files) ---------------------------
app.include_router(health.router)
app.include_router(assessment.router)

# --- Frontend ---------------------------------------------------------------
# Everything inside frontend/ is served under /static/...  e.g.
#   frontend/style.css  ->  GET /static/style.css
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "index.html")
