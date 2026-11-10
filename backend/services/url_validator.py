"""Target URL validation and SSRF-safe fetching.

Defence layers, outermost first:

1. Syntax: http/https only, no credentials, no backslashes or control
   characters, allowed ports only, no single-label or internal-looking
   hostnames, no non-standard numeric IPs (``2130706433``, ``0x7f.1``).
   The URL is then rebuilt from its parsed parts, so the string we fetch is
   exactly what we validated (this avoids differences between URL parsers).
2. Pre-flight DNS: resolve the hostname and reject it if ANY address is
   non-public. The resolved IP is never shown to the caller, so the API can't
   be used to probe internal DNS.
3. Connection-time pinning (the actual guard against DNS rebinding):
   ``_GuardedConnection._new_conn`` resolves the hostname again, validates
   every address, and opens the TCP socket to the validated IP itself. The
   address that was checked is the one used, so there is no gap between check
   and connect. TLS SNI and certificate checks still use the real hostname.
4. Redirects are followed manually (``allow_redirects=False``). Every hop goes
   through layers 1-3 again, with a hop limit and loop detection.
5. Resource limits: one wall-clock deadline for the whole redirect chain, a
   streamed body capped at MAX_RESPONSE_BYTES of *decoded* data (so
   gzip bombs are limited too), proxies from the environment ignored
   (``trust_env=False``), and no automatic retries.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
from bs4 import BeautifulSoup
from pydantic import BaseModel
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError, NewConnectionError
from urllib3.util.connection import create_connection

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
REQUEST_TIMEOUT_S = 10.0          # total wall-clock budget for the whole redirect chain
CONNECT_TIMEOUT_S = 5.0           # per TCP connect (bounded by what remains of the budget)
DNS_TIMEOUT_S = 3.0               # getaddrinfo has no timeout of its own
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_REDIRECTS = 5
MAX_URL_LENGTH = 2048
CHUNK_SIZE = 16 * 1024            # small chunks keep the decompression overshoot small
ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443, 8080, 8443}

# Looks like a normal browser so we're served the same HTML a shopper sees,
# with an honest product token at the end so site owners can identify us.
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 StoreAssessmentBot/0.2"
)
DEFAULT_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",  # no brotli: the decoder isn't guaranteed to be installed
}

BLOCKED_HOST_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa", ".intranet")
BLOCKED_HOSTNAMES = {"localhost", "localhost.localdomain", "metadata.google.internal"}

# Explicitly blocked ranges. ``ip.is_global`` below catches the rest, but the
# required ranges are listed here so the policy can be read and audited.
BLOCKED_NETWORKS = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8",          # "this network"
    "10.0.0.0/8",         # RFC 1918
    "100.64.0.0/10",      # carrier-grade NAT
    "127.0.0.0/8",        # loopback
    "169.254.0.0/16",     # link-local (incl. 169.254.169.254 cloud metadata)
    "172.16.0.0/12",      # RFC 1918
    "192.0.0.0/24",       # IETF protocol assignments
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",  # documentation
    "192.168.0.0/16",     # RFC 1918
    "198.18.0.0/15",      # benchmarking
    "224.0.0.0/4",        # multicast
    "240.0.0.0/4",        # reserved, incl. 255.255.255.255
    "::/128", "::1/128",  # unspecified, loopback
    "fc00::/7",           # unique local (incl. fd00:ec2::254 AWS IMDS over IPv6)
    "fe80::/10",          # link-local
    "ff00::/8",           # multicast
    "2001:db8::/32",      # documentation
    "2001::/32",          # Teredo tunnelling
)]
NAT64_NETWORKS = [ipaddress.ip_network(n) for n in ("64:ff9b::/96", "64:ff9b:1::/48")]

_NUMERIC_LABEL = re.compile(r"^(0x[0-9a-f]*|[0-9]+)$", re.IGNORECASE)
_FORBIDDEN_CHARS = re.compile(r"[\x00-\x20\x7f\\]")

_dns_pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="dns")


# --------------------------------------------------------------------------
# Errors and result models
# --------------------------------------------------------------------------
class ErrorCode(str, Enum):
    INVALID_URL = "invalid_url"
    UNSAFE_TARGET = "unsafe_target"
    DNS_FAILURE = "dns_failure"
    TIMEOUT = "timeout"
    CONNECTION_ERROR = "connection_error"
    TLS_ERROR = "tls_error"
    TOO_MANY_REDIRECTS = "too_many_redirects"
    REDIRECT_LOOP = "redirect_loop"
    RESPONSE_TOO_LARGE = "response_too_large"
    HTTP_ERROR = "http_error"
    BOT_PROTECTION = "bot_protection"


#: Errors caused by the submitted URL itself (the route returns HTTP 400 for these).
CLIENT_ERROR_CODES = {ErrorCode.INVALID_URL, ErrorCode.UNSAFE_TARGET}


class TargetError(Exception):
    """Base class. Deliberately NOT an OSError subclass: urllib3/requests catch
    OSError and wrap or retry it, but this must propagate untouched."""

    code: ErrorCode = ErrorCode.INVALID_URL

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class InvalidURLError(TargetError):
    code = ErrorCode.INVALID_URL


class UnsafeTargetError(TargetError):
    code = ErrorCode.UNSAFE_TARGET


class DNSResolutionError(TargetError):
    code = ErrorCode.DNS_FAILURE


class ValidationResult(BaseModel):
    original_url: str
    normalized_url: str | None = None
    final_url: str | None = None
    is_accessible: bool = False
    http_status: int | None = None
    page_title: str | None = None
    response_time_ms: int | None = None
    redirect_chain: list[str] = []
    error_code: ErrorCode | None = None
    error: str | None = None


@dataclass
class FetchResult:
    """Public result plus the raw material that later stages inspect."""

    result: ValidationResult
    headers: dict[str, str] = field(default_factory=dict)  # lower-cased names
    cookie_names: list[str] = field(default_factory=list)
    html: str = ""          # decoded body, only when the response is HTML
    text: str = ""          # decoded body for any textual type (HTML, JSON, XML, plain text)
    body: bytes = b""       # raw (transfer-decoded) body, e.g. for .xml.gz sitemaps
    content_type: str = ""


# --------------------------------------------------------------------------
# Layer 1: syntax
# --------------------------------------------------------------------------
def normalize_url(raw: str) -> str:
    """Validate the URL's syntax and return a canonical, rebuilt URL. Raises InvalidURLError."""
    if not isinstance(raw, str):
        raise InvalidURLError("URL must be a string.")
    url = raw.strip()
    if not url:
        raise InvalidURLError("URL is empty.")
    if len(url) > MAX_URL_LENGTH:
        raise InvalidURLError(f"URL is longer than {MAX_URL_LENGTH} characters.")
    if _FORBIDDEN_CHARS.search(url):
        raise InvalidURLError("URL contains whitespace, control characters or backslashes.")
    if "://" not in url:
        if re.match(r"^[a-z][a-z0-9+.-]*:", url, re.IGNORECASE) and not re.match(r"^[^:/]+:\d", url):
            raise InvalidURLError("Only http and https URLs are allowed.")  # e.g. javascript:, file:
        url = "https://" + url

    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise InvalidURLError(f"Malformed URL: {exc}") from None

    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise InvalidURLError("Only http and https URLs are allowed.")
    if "@" in parts.netloc:
        raise InvalidURLError("URLs containing credentials (user@host) are not allowed.")
    if not parts.hostname:
        raise InvalidURLError("URL has no hostname.")

    effective_port = port or (443 if scheme == "https" else 80)
    if effective_port not in ALLOWED_PORTS:
        raise InvalidURLError(f"Port {effective_port} is not allowed.")

    host = _normalize_host(parts.hostname)
    netloc = f"[{host}]" if ":" in host else host
    if port and port != (443 if scheme == "https" else 80):
        netloc += f":{port}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


def _normalize_host(hostname: str) -> str:
    host = hostname.lower().rstrip(".")
    if not host:
        raise InvalidURLError("URL has no hostname.")

    try:  # standard IPv4 / IPv6 literal
        ipaddress.ip_address(host.split("%")[0])
        return host
    except ValueError:
        pass

    labels = host.split(".")
    if all(_NUMERIC_LABEL.match(label) for label in labels):
        # Valid for inet_aton but not a dotted quad: 2130706433, 0x7f000001, 0177.0.0.1, 127.1
        raise InvalidURLError("Non-standard numeric IP address notation is not allowed.")

    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise InvalidURLError("Hostname is not a valid domain name.") from None
    if len(host) > 253 or any(not 0 < len(label) <= 63 for label in host.split(".")):
        raise InvalidURLError("Hostname is not a valid domain name.")
    if not re.fullmatch(r"[a-z0-9.-]+", host):
        raise InvalidURLError("Hostname contains invalid characters.")
    if "." not in host:
        raise UnsafeTargetError("Single-label hostnames are not allowed (they may resolve to internal hosts).")
    if host in BLOCKED_HOSTNAMES or host.endswith(BLOCKED_HOST_SUFFIXES):
        raise UnsafeTargetError("Hostname refers to a local or internal network.")
    return host


# --------------------------------------------------------------------------
# Layer 2: IP policy + DNS
# --------------------------------------------------------------------------
def is_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address):
        # Addresses that carry an IPv4 address inside them are judged by that IPv4 address.
        if ip.ipv4_mapped is not None:
            return is_public_ip(ip.ipv4_mapped)
        if ip.sixtofour is not None:
            return is_public_ip(ip.sixtofour)
        if any(ip in net for net in NAT64_NETWORKS):
            return is_public_ip(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    if any(ip.version == net.version and ip in net for net in BLOCKED_NETWORKS):
        return False
    return ip.is_global and not (ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def _system_resolve(host: str) -> list[str]:
    """Raw DNS lookup. Kept as a separate function so tests can replace it."""
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return [info[4][0] for info in infos]


def resolve_public_ips(host: str) -> list[str]:
    """Resolve ``host`` and return its IPs (IPv4 first) only if EVERY address is public.

    Rejecting the whole hostname when any record is private stops attacks that
    mix public and private records and rely on the client picking the private one.
    """
    try:
        literal = ipaddress.ip_address(host.strip("[]").split("%")[0])
    except ValueError:
        literal = None

    if literal is not None:
        addresses = [literal]
    else:
        future = _dns_pool.submit(_system_resolve, host)
        try:
            raw = future.result(timeout=DNS_TIMEOUT_S)
        except FutureTimeout:
            raise DNSResolutionError(f"DNS lookup for {host} timed out.") from None
        except (socket.gaierror, UnicodeError, OSError):
            raise DNSResolutionError(f"Could not resolve hostname {host}.") from None
        addresses = []
        for value in raw:
            try:
                ip = ipaddress.ip_address(value.split("%")[0])
            except ValueError:
                continue
            if ip not in addresses:
                addresses.append(ip)
        if not addresses:
            raise DNSResolutionError(f"Could not resolve hostname {host}.")

    if not all(is_public_ip(ip) for ip in addresses):
        # Deliberately don't name the IP (avoids leaking internal DNS data).
        raise UnsafeTargetError("Target resolves to a private, loopback, link-local or reserved IP address.")

    addresses.sort(key=lambda ip: ip.version)  # IPv4 first; IPv6 is often unreachable from servers
    return [str(ip) for ip in addresses]


# --------------------------------------------------------------------------
# Layer 3: connection-time pinning
# --------------------------------------------------------------------------
class _GuardedConnectionMixin:
    """Replaces urllib3's ``_new_conn`` so the socket only ever connects to an
    address that passed ``resolve_public_ips`` in this same call.

    We do NOT change ``self._dns_host``: in urllib3 2.x ``self.host`` is derived
    from it, and ``self.host`` is used for TLS SNI and certificate checks.
    """

    def _new_conn(self):  # type: ignore[override]
        if self.port not in ALLOWED_PORTS:
            raise UnsafeTargetError(f"Port {self.port} is not allowed.")
        ips = resolve_public_ips(self.host)
        last_exc: Exception | None = None
        for ip in ips:
            try:
                return create_connection(
                    (ip, self.port),
                    self.timeout,
                    source_address=self.source_address,
                    socket_options=self.socket_options,
                )
            except socket.timeout as exc:
                last_exc = ConnectTimeoutError(self, f"Connection to {self.host} timed out.")
                last_exc.__cause__ = exc
            except OSError as exc:
                last_exc = NewConnectionError(self, f"Failed to establish a new connection: {exc}")
                last_exc.__cause__ = exc
        assert last_exc is not None
        raise last_exc


class _GuardedHTTPConnection(_GuardedConnectionMixin, HTTPConnection):
    pass


class _GuardedHTTPSConnection(_GuardedConnectionMixin, HTTPSConnection):
    pass


class _GuardedHTTPPool(HTTPConnectionPool):
    ConnectionCls = _GuardedHTTPConnection


class _GuardedHTTPSPool(HTTPSConnectionPool):
    ConnectionCls = _GuardedHTTPSConnection


class GuardedAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = {"http": _GuardedHTTPPool, "https": _GuardedHTTPSPool}

    def proxy_manager_for(self, proxy, **kwargs):  # never route through a proxy
        raise UnsafeTargetError("Proxies are not permitted.")


def build_session() -> requests.Session:
    """A requests Session where every connection is checked against the SSRF policy.
    Later stages should reuse this for all outbound HTTP."""
    session = requests.Session()
    session.trust_env = False            # ignore HTTP(S)_PROXY, .netrc, etc.
    session.max_redirects = 0
    session.headers.update(DEFAULT_HEADERS)
    adapter = GuardedAdapter(max_retries=0, pool_connections=4, pool_maxsize=4)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def _send(session: requests.Session, url: str, timeout: tuple[float, float]) -> requests.Response:
    """Send a single HTTP request. Kept separate so tests can replace it."""
    return session.get(url, allow_redirects=False, stream=True, timeout=timeout)


# --------------------------------------------------------------------------
# Body reading + page helpers
# --------------------------------------------------------------------------
class _BodyTooLarge(Exception):
    pass


class _DeadlineExceeded(Exception):
    pass


def _read_capped(response: requests.Response, deadline: float, max_bytes: int = MAX_RESPONSE_BYTES) -> bytes:
    declared = response.headers.get("Content-Length")
    if declared and declared.isdigit() and int(declared) > max_bytes:
        raise _BodyTooLarge()
    buf = bytearray()
    for chunk in response.iter_content(chunk_size=CHUNK_SIZE):  # decoded (decompressed) bytes
        buf += chunk
        if len(buf) > max_bytes:
            raise _BodyTooLarge()
        if time.monotonic() > deadline:  # read timeout is per chunk; this bounds the total
            raise _DeadlineExceeded()
    return bytes(buf)


def _decode(body: bytes, content_type: str) -> str:
    match = re.search(r"charset=([\w.-]+)", content_type, re.IGNORECASE)
    if not match:
        meta = re.search(rb"<meta[^>]+charset=[\"']?([\w.-]+)", body[:4096], re.IGNORECASE)
        charset = meta.group(1).decode("ascii", "ignore") if meta else "utf-8"
    else:
        charset = match.group(1)
    try:
        return body.decode(charset, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def extract_title(html: str) -> str | None:
    if not html:
        return None
    soup = BeautifulSoup(html, "html.parser")
    if soup.title and soup.title.string:
        title = " ".join(soup.title.string.split())
        return title[:300] or None
    return None


def _looks_like_bot_challenge(status: int, headers: dict[str, str], html: str) -> bool:
    if status not in (403, 429, 503):
        return False
    if headers.get("cf-mitigated", "").lower() == "challenge" or "x-datadome" in headers:
        return True
    head = html[:20000].lower()
    markers = ("cf-chl", "challenge-platform", "just a moment...", "_incapsula_resource",
               "attention required! | cloudflare", "px-captcha", "captcha-delivery.com")
    return any(m in head for m in markers)


def _cookie_names(response: requests.Response) -> list[str]:
    names: list[str] = []
    raw_headers = getattr(getattr(response, "raw", None), "headers", None)
    values = raw_headers.getlist("Set-Cookie") if hasattr(raw_headers, "getlist") else []
    for value in values:
        name = value.split("=", 1)[0].strip()
        if name and name not in names:
            names.append(name)
    for name in getattr(response, "cookies", {}).keys():
        if name not in names:
            names.append(name)
    return names


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------
_TEXTUAL = re.compile(r"html|json|xml|text/|javascript|rss|atom", re.IGNORECASE)


def validate_target(
    raw_url: str,
    *,
    timeout_s: float | None = None,
    max_bytes: int = MAX_RESPONSE_BYTES,
    accept: str | None = None,
) -> FetchResult:
    """Validate, resolve and fetch ``raw_url`` safely. Never raises for target
    problems; every failure is reported through ``error_code`` / ``error``.

    This is the ONLY function that should make outbound requests to a target
    site. ``timeout_s`` and ``max_bytes`` can only be lowered from the defaults.
    """
    result = ValidationResult(original_url=raw_url)
    fetch = FetchResult(result=result)
    started = time.monotonic()
    budget = REQUEST_TIMEOUT_S if timeout_s is None else max(0.0, min(timeout_s, REQUEST_TIMEOUT_S))
    max_bytes = max(0, min(max_bytes, MAX_RESPONSE_BYTES))
    deadline = started + budget

    def fail(code: ErrorCode, message: str) -> FetchResult:
        result.error_code, result.error = code, message
        result.response_time_ms = int((time.monotonic() - started) * 1000)
        return fetch

    try:
        url = normalize_url(raw_url)
        result.normalized_url = url
        resolve_public_ips(urlsplit(url).hostname or "")  # pre-flight, for a clear early error
    except TargetError as exc:
        return fail(exc.code, exc.message)

    session = build_session()
    if accept:
        session.headers["Accept"] = accept
    seen: set[str] = set()
    try:
        for hop in range(MAX_REDIRECTS + 1):
            if url in seen:
                return fail(ErrorCode.REDIRECT_LOOP, "Redirect loop detected.")
            seen.add(url)
            result.redirect_chain.append(url)

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return fail(ErrorCode.TIMEOUT, f"Request exceeded the {budget:.0f}s time limit.")
            timeout = (min(CONNECT_TIMEOUT_S, remaining), remaining)

            response = _send(session, url, timeout)
            try:
                status = response.status_code
                headers = {k.lower(): v for k, v in response.headers.items()}

                if 300 <= status < 400 and "location" in headers:
                    if hop == MAX_REDIRECTS:
                        return fail(ErrorCode.TOO_MANY_REDIRECTS, f"More than {MAX_REDIRECTS} redirects.")
                    try:
                        url = normalize_url(urljoin(url, headers["location"]))
                        resolve_public_ips(urlsplit(url).hostname or "")
                    except TargetError as exc:
                        result.http_status = status
                        return fail(exc.code, f"Redirect blocked: {exc.message}")
                    continue

                # Final response
                content_type = headers.get("content-type", "")
                body = _read_capped(response, deadline, max_bytes)
                is_html = "html" in content_type.lower() or not content_type
                text = _decode(body, content_type) if (is_html or _TEXTUAL.search(content_type)) else ""
                html = text if is_html else ""

                result.final_url = url
                result.http_status = status
                result.page_title = extract_title(html)
                result.response_time_ms = int((time.monotonic() - started) * 1000)
                fetch.headers, fetch.html, fetch.content_type = headers, html, content_type
                fetch.text, fetch.body = text, body
                fetch.cookie_names = _cookie_names(response)

                if 200 <= status < 300:
                    result.is_accessible = True
                elif _looks_like_bot_challenge(status, headers, html):
                    result.error_code = ErrorCode.BOT_PROTECTION
                    result.error = f"HTTP {status}: the site returned a bot-protection challenge."
                else:
                    result.error_code = ErrorCode.HTTP_ERROR
                    result.error = f"The site responded with HTTP {status}."
                return fetch
            finally:
                response.close()

        return fail(ErrorCode.TOO_MANY_REDIRECTS, f"More than {MAX_REDIRECTS} redirects.")

    except TargetError as exc:  # raised at connection time (e.g. DNS rebinding)
        return fail(exc.code, exc.message)
    except _BodyTooLarge:
        return fail(ErrorCode.RESPONSE_TOO_LARGE, f"Response exceeded the {max_bytes:,} byte limit.")
    except (_DeadlineExceeded, requests.exceptions.Timeout):
        return fail(ErrorCode.TIMEOUT, f"Request exceeded the {budget:.0f}s time limit.")
    except requests.exceptions.SSLError:
        return fail(ErrorCode.TLS_ERROR, "TLS/SSL handshake or certificate verification failed.")
    except requests.exceptions.ConnectionError:
        return fail(ErrorCode.CONNECTION_ERROR, "Could not connect to the website.")
    except requests.exceptions.RequestException as exc:
        return fail(ErrorCode.CONNECTION_ERROR, f"Request failed: {type(exc).__name__}.")
    finally:
        session.close()
