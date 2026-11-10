from __future__ import annotations

import ipaddress

import pytest
import requests

from services import url_validator as uv
from services.url_validator import ErrorCode, validate_target
from tests.conftest import PUBLIC_IP, FakeResponse

HTML_OK = b"<html><head><title>  Demo   Store </title></head><body>hi</body></html>"


# ---------------------------------------------------------------- syntax
@pytest.mark.parametrize("url", [
    "ftp://example.com/",
    "file:///etc/passwd",
    "javascript:alert(1)",
    "gopher://example.com/",
    "http://user:pass@example.com/",
    "http://example.com@169.254.169.254/",
    "http://example.com\\@127.0.0.1/",
    "http://exa mple.com/",
    "http://example.com:22/",
    "http://example.com:6379/",
    "http://2130706433/",          # decimal 127.0.0.1
    "http://0x7f000001/",          # hex 127.0.0.1
    "http://0177.0.0.1/",          # octal
    "http://127.1/",               # short form
    "http:///nohost",
    "",
    "https://" + "a" * 3000 + ".com",
])
def test_invalid_urls_rejected(url):
    with pytest.raises(uv.TargetError):
        uv.normalize_url(url)


@pytest.mark.parametrize("url", [
    "http://localhost/",
    "http://LOCALHOST./",
    "http://foo.localhost/",
    "http://printer.local/",
    "http://metadata.google.internal/",
    "http://intranet/",            # single label -> resolver search domains
])
def test_internal_hostnames_rejected_before_dns(url):
    with pytest.raises(uv.UnsafeTargetError):
        uv.normalize_url(url)


@pytest.mark.parametrize("raw,expected", [
    ("example.com", "https://example.com/"),
    ("HTTPS://Example.COM", "https://example.com/"),
    ("https://example.com:443/a?b=1#frag", "https://example.com/a?b=1"),
    ("http://example.com:8080/x", "http://example.com:8080/x"),
    ("https://bücher.de/", "https://xn--bcher-kva.de/"),
])
def test_normalization(raw, expected):
    assert uv.normalize_url(raw) == expected


# ---------------------------------------------------------------- IP policy
@pytest.mark.parametrize("ip", [
    "0.0.0.0", "10.1.2.3", "100.64.0.1", "127.0.0.1", "169.254.169.254", "172.16.0.1",
    "172.31.255.255", "192.168.1.1", "224.0.0.1", "255.255.255.255", "198.18.0.1",
    "::", "::1", "fc00::1", "fd00:ec2::254", "fe80::1", "ff02::1",
    "::ffff:127.0.0.1", "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "2002:7f00:1::",
])
def test_private_ips_blocked(ip):
    assert not uv.is_public_ip(ipaddress.ip_address(ip))


@pytest.mark.parametrize("ip", ["93.184.215.14", "8.8.8.8", "2606:4700::6810:84e5", "::ffff:8.8.8.8"])
def test_public_ips_allowed(ip):
    assert uv.is_public_ip(ipaddress.ip_address(ip))


# ---------------------------------------------------------------- validate_target: unsafe
@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/",   # AWS metadata
    "http://127.0.0.1/",
    "http://[::1]/",
    "http://10.0.0.5/",
    "http://192.168.0.1/",
    "http://0.0.0.0/",
    "http://[::ffff:169.254.169.254]/",
    "http://[fd00:ec2::254]/",
    "http://localhost:8000/",
])
def test_unsafe_literal_targets(url, fake_dns, fake_http):
    res = validate_target(url).result
    assert res.error_code in (ErrorCode.UNSAFE_TARGET, ErrorCode.INVALID_URL)
    assert res.is_accessible is False
    assert fake_http.calls == []          # nothing was ever requested


def test_hostname_resolving_to_metadata_ip_blocked(fake_dns, fake_http):
    fake_dns["evil.example.com"] = ["169.254.169.254"]
    res = validate_target("http://evil.example.com/").result
    assert res.error_code == ErrorCode.UNSAFE_TARGET
    assert "169.254" not in (res.error or "")   # resolved IP is not leaked
    assert fake_http.calls == []


def test_mixed_public_and_private_records_blocked(fake_dns, fake_http):
    fake_dns["mixed.example.com"] = [PUBLIC_IP, "10.0.0.1"]
    assert validate_target("https://mixed.example.com/").result.error_code == ErrorCode.UNSAFE_TARGET


def test_dns_failure(fake_dns, fake_http):
    res = validate_target("https://does-not-exist.example/").result
    assert res.error_code == ErrorCode.DNS_FAILURE


# ---------------------------------------------------------------- connection-time guard
def test_guarded_session_refuses_private_ip_even_without_preflight():
    """Code that skips validate_target and uses the session directly is still protected."""
    with pytest.raises(uv.UnsafeTargetError):
        uv.build_session().get("http://127.0.0.1/", timeout=2)


def test_guarded_session_refuses_disallowed_port():
    with pytest.raises(uv.UnsafeTargetError):
        uv.build_session().get("http://93.184.215.14:22/", timeout=2)


def test_dns_rebinding_blocked_at_connect_time(fake_dns):
    """Pre-flight sees a public IP, but at connect time DNS returns loopback."""
    answers = iter([[PUBLIC_IP], ["127.0.0.1"]])
    fake_dns["rebind.example.com"] = lambda: next(answers)
    res = validate_target("http://rebind.example.com/").result
    assert res.error_code == ErrorCode.UNSAFE_TARGET
    assert res.is_accessible is False


# ---------------------------------------------------------------- redirects
def test_redirect_to_private_ip_blocked(fake_dns, fake_http):
    fake_dns["shop.example.com"] = [PUBLIC_IP]
    fake_http["https://shop.example.com/"] = FakeResponse(302, {"Location": "http://169.254.169.254/latest/meta-data/"})
    res = validate_target("https://shop.example.com/").result
    assert res.error_code == ErrorCode.UNSAFE_TARGET
    assert res.error.startswith("Redirect blocked")
    assert fake_http.calls == ["https://shop.example.com/"]


def test_redirect_to_hostname_resolving_private_blocked(fake_dns, fake_http):
    fake_dns["shop.example.com"] = [PUBLIC_IP]
    fake_dns["internal.example.com"] = ["10.0.0.7"]
    fake_http["https://shop.example.com/"] = FakeResponse(301, {"Location": "https://internal.example.com/admin"})
    assert validate_target("https://shop.example.com/").result.error_code == ErrorCode.UNSAFE_TARGET


def test_redirect_to_non_http_scheme_blocked(fake_dns, fake_http):
    fake_dns["shop.example.com"] = [PUBLIC_IP]
    fake_http["https://shop.example.com/"] = FakeResponse(302, {"Location": "file:///etc/passwd"})
    assert validate_target("https://shop.example.com/").result.error_code == ErrorCode.INVALID_URL


def test_safe_redirect_followed(fake_dns, fake_http):
    fake_dns["shop.example.com"] = [PUBLIC_IP]
    fake_dns["www.shop.example.com"] = [PUBLIC_IP]
    fake_http["http://shop.example.com/"] = FakeResponse(301, {"Location": "https://www.shop.example.com/"})
    fake_http["https://www.shop.example.com/"] = FakeResponse(200, {"Content-Type": "text/html; charset=utf-8"}, HTML_OK)
    res = validate_target("http://shop.example.com").result
    assert res.is_accessible and res.http_status == 200
    assert res.final_url == "https://www.shop.example.com/"
    assert res.redirect_chain == ["http://shop.example.com/", "https://www.shop.example.com/"]


def test_redirect_loop_detected(fake_dns, fake_http):
    fake_dns["a.example.com"] = [PUBLIC_IP]
    fake_http["https://a.example.com/"] = FakeResponse(302, {"Location": "/x"})
    fake_http["https://a.example.com/x"] = FakeResponse(302, {"Location": "/"})
    assert validate_target("https://a.example.com/").result.error_code == ErrorCode.REDIRECT_LOOP


def test_too_many_redirects(fake_dns, fake_http):
    fake_dns["a.example.com"] = [PUBLIC_IP]
    for i in range(10):
        fake_http[f"https://a.example.com/{i}"] = FakeResponse(302, {"Location": f"/{i + 1}"})
    res = validate_target("https://a.example.com/0").result
    assert res.error_code == ErrorCode.TOO_MANY_REDIRECTS
    assert len(fake_http.calls) == uv.MAX_REDIRECTS + 1


# ---------------------------------------------------------------- success + limits
def test_safe_public_url(fake_dns, fake_http):
    fake_dns["store.example.com"] = [PUBLIC_IP]
    fake_http["https://store.example.com/"] = FakeResponse(200, {"Content-Type": "text/html"}, HTML_OK)
    fetch = validate_target("store.example.com")
    res = fetch.result
    assert res.original_url == "store.example.com"
    assert res.is_accessible is True
    assert res.http_status == 200
    assert res.page_title == "Demo Store"
    assert res.error is None and res.error_code is None
    assert isinstance(res.response_time_ms, int)
    assert "<title>" in fetch.html


def test_body_size_cap(fake_dns, fake_http):
    fake_dns["big.example.com"] = [PUBLIC_IP]
    chunk = b"x" * (1024 * 1024)
    resp = FakeResponse(200, {"Content-Type": "text/html"}, chunks=[chunk] * 6)
    fake_http["https://big.example.com/"] = resp
    res = validate_target("https://big.example.com/").result
    assert res.error_code == ErrorCode.RESPONSE_TOO_LARGE
    assert resp.closed


def test_declared_content_length_cap(fake_dns, fake_http):
    fake_dns["big.example.com"] = [PUBLIC_IP]
    fake_http["https://big.example.com/"] = FakeResponse(200, {"Content-Length": str(50 * 1024 * 1024)}, chunks=[])
    assert validate_target("https://big.example.com/").result.error_code == ErrorCode.RESPONSE_TOO_LARGE


def test_timeout(fake_dns, fake_http):
    fake_dns["slow.example.com"] = [PUBLIC_IP]
    fake_http["https://slow.example.com/"] = requests.exceptions.ReadTimeout()
    assert validate_target("https://slow.example.com/").result.error_code == ErrorCode.TIMEOUT


def test_http_error_status(fake_dns, fake_http):
    fake_dns["gone.example.com"] = [PUBLIC_IP]
    fake_http["https://gone.example.com/"] = FakeResponse(404, {"Content-Type": "text/html"}, b"<title>Not found</title>")
    res = validate_target("https://gone.example.com/").result
    assert res.is_accessible is False and res.http_status == 404
    assert res.error_code == ErrorCode.HTTP_ERROR


def test_bot_challenge_detected(fake_dns, fake_http):
    fake_dns["cf.example.com"] = [PUBLIC_IP]
    fake_http["https://cf.example.com/"] = FakeResponse(
        403, {"Content-Type": "text/html", "cf-mitigated": "challenge"}, b"<title>Just a moment...</title>")
    assert validate_target("https://cf.example.com/").result.error_code == ErrorCode.BOT_PROTECTION


def test_user_agent_is_set():
    ua = uv.build_session().headers["User-Agent"]
    assert ua.startswith("Mozilla/5.0") and "StoreAssessmentBot" in ua
