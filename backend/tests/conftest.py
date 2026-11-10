"""Shared fixtures. Tests never touch the real network: DNS and HTTP are faked."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest
from requests.structures import CaseInsensitiveDict

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))
os.environ.setdefault("ASSESSMENT_DB_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))

from services import url_validator  # noqa: E402

PUBLIC_IP = "93.184.215.14"


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    """Each test gets a fresh SQLite file and an empty rate-limit window."""
    from database import connection
    from services.rate_limit import assessment_limiter

    monkeypatch.setattr(connection, "DB_PATH", tmp_path / "test.db")
    connection.init_db()
    assessment_limiter.reset()
    yield
    assessment_limiter.reset()


@pytest.fixture
def fake_dns(monkeypatch):
    """Map hostname -> list of IPs. Unknown hosts fail resolution."""
    table: dict[str, list[str]] = {}

    def resolve(host: str) -> list[str]:
        if host in table:
            value = table[host]
            return value() if callable(value) else list(value)
        raise OSError(f"no such host {host}")

    monkeypatch.setattr(url_validator, "_system_resolve", resolve)
    return table


class FakeResponse:
    def __init__(self, status=200, headers=None, body=b"", chunks=None):
        self.status_code = status
        self.headers = CaseInsensitiveDict(headers or {})
        self._chunks = chunks if chunks is not None else [body]
        self.cookies = {}
        self.closed = False

    def iter_content(self, chunk_size=1):
        yield from self._chunks

    def close(self):
        self.closed = True


@pytest.fixture
def fake_http(monkeypatch):
    """Map normalized URL -> FakeResponse (or an exception to raise). Records each requested URL."""
    class Routes(dict):
        calls: list[str]
        default: object = None   # e.g. lambda: FakeResponse(404); None = fail on unknown URLs

    routes = Routes()
    calls: list[str] = []

    def send(session, url, timeout):
        calls.append(url)
        if url not in routes:
            if routes.default is None:
                raise AssertionError(f"unexpected request to {url}")
            return routes.default()
        value = routes[url]
        if callable(value) and not isinstance(value, BaseException):
            value = value()
        if isinstance(value, BaseException):
            raise value
        return value

    monkeypatch.setattr(url_validator, "_send", send)
    routes.calls = calls
    return routes
