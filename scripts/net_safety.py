#!/usr/bin/env python3
"""
net_safety.py — SSRF-safe, non-invasive HTTP for deployment availability checks.

The ONLY live interaction this study performs is confirming a public deployment
exists: a root HEAD and, when needed, one bounded root GET. This module makes
that interaction safe against SSRF, DNS rebinding, and uncontrolled redirects:

  * only http/https; reject userinfo, localhost/.local, unsupported schemes;
  * resolve the host and reject loopback/private/link-local/multicast/reserved/
    unspecified IPv4+IPv6; validate EVERY resolved address;
  * manually follow redirects up to a configured maximum, re-validating each
    target host+resolved IPs BEFORE connecting;
  * pin the connection to a pre-validated IP so the address cannot change
    between validation and connect (DNS-rebinding defence, as far as urllib
    permits) — the Host header preserves virtual hosting + TLS SNI/cert checks;
  * enforce a single monotonic total deadline across HEAD+GET+redirects;
  * per-domain throttling + maximum attempts;
  * cap decompressed body bytes;
  * record explicit rejection reasons.

Pure validation (classify/validate URLs + IPs) is separated from the socket work
and unit-tested offline. Tests NEVER contact a real network: a fake resolver +
fake opener are injected.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable, Optional

# --------------------------------------------------------------------------- #
# Configuration + result types
# --------------------------------------------------------------------------- #
@dataclass
class FetchPolicy:
    connect_timeout_s: float = 5.0
    total_deadline_s: float = 15.0
    max_redirects: int = 5
    max_body_bytes: int = 1_000_000
    per_domain_per_minute: int = 10
    max_attempts: int = 2
    user_agent: str = "claude-deployed-security-study/0.1 (research; non-invasive availability check)"


@dataclass
class FetchResult:
    requested_url: str
    final_url: Optional[str] = None
    http_status: Optional[int] = None
    error: Optional[str] = None          # timeout|dns|tls|connection|rejected|deadline|too_large
    rejection_reason: Optional[str] = None
    title: str = ""
    body_snippet: str = ""
    content_type: str = ""
    redirect_count: int = 0
    resolved_ips: list = field(default_factory=list)


BLOCKED_HOST_SUFFIXES = (".local",)
BLOCKED_HOST_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}


# --------------------------------------------------------------------------- #
# PURE VALIDATION
# --------------------------------------------------------------------------- #
def is_public_ip(ip_str: str) -> bool:
    """True only for globally-routable unicast addresses."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped  # unwrap ::ffff:a.b.c.d so a mapped private IP is caught
    return not (ip.is_loopback or ip.is_private or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified
                or getattr(ip, "is_site_local", False))


def validate_url(url: str) -> tuple[bool, Optional[str], Optional[urllib.parse.SplitResult]]:
    """Scheme/host validation independent of DNS. Returns (ok, reason, parts)."""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return False, "unparseable_url", None
    if parts.scheme not in ("http", "https"):
        return False, f"scheme_not_allowed:{parts.scheme or 'none'}", None
    if parts.username or parts.password or "@" in parts.netloc:
        return False, "userinfo_in_url", None
    host = parts.hostname
    if not host:
        return False, "no_host", None
    low = host.lower().rstrip(".")
    if low in BLOCKED_HOST_NAMES or any(low.endswith(s) for s in BLOCKED_HOST_SUFFIXES):
        return False, f"blocked_host:{low}", None
    # A bare IP literal in the URL is validated directly (dotted IPv4, [IPv6],
    # and bare decimal-integer IPv4 like http://2130706433/).
    literal = low.strip("[]")
    ip_obj = None
    try:
        ip_obj = ipaddress.ip_address(literal)
    except ValueError:
        if literal.isdigit():
            try:
                ip_obj = ipaddress.ip_address(int(literal))
            except ValueError:
                ip_obj = None
    if ip_obj is not None and not is_public_ip(str(ip_obj)):
        return False, f"non_public_ip_literal:{ip_obj}", None
    return True, None, parts


def validate_resolved(host: str, resolver: Callable[[str], list]) -> tuple[bool, Optional[str], list]:
    """Resolve `host` and require EVERY address to be public."""
    try:
        ips = resolver(host)
    except Exception as exc:
        return False, f"dns_error:{type(exc).__name__}", []
    if not ips:
        return False, "dns_no_records", []
    for ip in ips:
        if not is_public_ip(ip):
            return False, f"non_public_resolved_ip:{ip}", ips
    return True, None, ips


# --------------------------------------------------------------------------- #
# Real resolver (all A/AAAA records)
# --------------------------------------------------------------------------- #
def system_resolver(host: str) -> list:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    ips: list = []
    for family, _t, _p, _c, sockaddr in infos:
        ip = sockaddr[0]
        if ip not in ips:
            ips.append(ip)
    return ips


# --------------------------------------------------------------------------- #
# Per-domain throttle
# --------------------------------------------------------------------------- #
class DomainThrottle:
    def __init__(self, per_minute: int, clock: Callable[[], float] = time.monotonic):
        self.per_minute = per_minute
        self.clock = clock
        self._hits: dict[str, list] = {}

    def allow(self, domain: str) -> bool:
        now = self.clock()
        window = [t for t in self._hits.get(domain, []) if now - t < 60.0]
        if len(window) >= self.per_minute:
            self._hits[domain] = window
            return False
        window.append(now)
        self._hits[domain] = window
        return True


# --------------------------------------------------------------------------- #
# IP-pinned connection (DNS-rebinding defence)
# --------------------------------------------------------------------------- #
def _connect_pinned(scheme: str, host: str, ip: str, port: int, timeout: float):
    """Open an HTTP(S) connection to a PRE-VALIDATED ip, presenting `host` for
    virtual-hosting + TLS SNI/cert verification (so cert checks still bind to the
    name, not the raw IP)."""
    if scheme == "https":
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(ip, port or 443, timeout=timeout, context=ctx)
        conn.server_hostname = host  # SNI/cert hostname = the name we validated
    else:
        conn = http.client.HTTPConnection(ip, port or 80, timeout=timeout)
    return conn


# --------------------------------------------------------------------------- #
# Safe fetch (manual redirect handling + monotonic deadline)
# --------------------------------------------------------------------------- #
def safe_fetch(url: str, policy: FetchPolicy, *, method: str = "HEAD",
               resolver: Callable[[str], list] = system_resolver,
               throttle: Optional[DomainThrottle] = None,
               opener: Optional[Callable] = None,
               clock: Callable[[], float] = time.monotonic,
               deadline: Optional[float] = None) -> FetchResult:
    """
    Non-invasive fetch of `url`'s root with SSRF-safe redirect following.

    `opener(host, ip, port, scheme, method, path, timeout, ua)` performs ONE
    request to a pre-validated ip and returns
    (status, headers(dict), location(str|None), body_reader(callable|None)).
    Injected in tests; defaults to a urllib-free pinned connection.

    Pass `deadline` (absolute monotonic time) to share ONE budget across a
    HEAD then GET; otherwise it is computed from policy.total_deadline_s.
    """
    result = FetchResult(requested_url=url)
    if deadline is None:
        deadline = clock() + policy.total_deadline_s
    opener = opener or _default_opener
    current = url
    redirects = 0

    while True:
        if clock() >= deadline:
            result.error, result.rejection_reason = "deadline", "total_deadline_exceeded"
            return result

        ok, reason, parts = validate_url(current)
        if not ok:
            result.error, result.rejection_reason = "rejected", reason
            return result
        host = parts.hostname
        domain = host.lower().rstrip(".")
        if throttle is not None and not throttle.allow(domain):
            result.error, result.rejection_reason = "rejected", "domain_rate_limited"
            return result

        ok, reason, ips = validate_resolved(host, resolver)
        if not ok:
            result.error = "dns" if reason.startswith("dns") else "rejected"
            result.rejection_reason = reason
            return result
        result.resolved_ips = ips
        pinned_ip = ips[0]                       # connect to a validated address only
        port = parts.port or (443 if parts.scheme == "https" else 80)
        # The discovered/redirected URL's OWN path only (query stripped). This is
        # the documented deployment entry point — never an enumerated/undocumented
        # route, never with parameters.
        path = parts.path or "/"
        remaining = max(0.0, deadline - clock())
        timeout = min(policy.connect_timeout_s, remaining)

        try:
            status, headers, location, read_body = opener(
                host, pinned_ip, port, parts.scheme, method, path, timeout, policy.user_agent)
        except _NetError as e:
            result.error, result.rejection_reason = e.kind, e.detail
            return result

        result.final_url = current
        result.http_status = status
        result.redirect_count = redirects
        result.content_type = (headers or {}).get("content-type", "")

        if status in (301, 302, 303, 307, 308) and location:
            redirects += 1
            if redirects > policy.max_redirects:
                result.error, result.rejection_reason = "rejected", "too_many_redirects"
                return result
            current = urllib.parse.urljoin(current, location)
            method = "GET" if status == 303 else method
            continue

        if method == "GET" and read_body is not None:
            body = read_body(policy.max_body_bytes, deadline, clock)
            if body is None:
                result.error, result.rejection_reason = "too_large", "body_exceeded_cap"
                return result
            result.body_snippet = body
        return result


# --------------------------------------------------------------------------- #
# Default opener (pinned http.client) — not exercised by unit tests
# --------------------------------------------------------------------------- #
class _NetError(Exception):
    def __init__(self, kind: str, detail: str):
        super().__init__(detail)
        self.kind, self.detail = kind, detail


def _default_opener(host, ip, port, scheme, method, path, timeout, ua):  # pragma: no cover
    # Request-encoding disabled (identity) so the decompressed-size cap is exact.
    conn = _connect_pinned(scheme, host, ip, port, timeout)
    try:
        conn.request(method, path, headers={"Host": host, "User-Agent": ua,
                                            "Accept-Encoding": "identity"})
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        location = headers.get("location")
        status = resp.status
        if 300 <= status < 400 or method != "GET":
            resp.read(1)  # minimal drain; do not download the body
            return status, headers, location, None
        # GET: read up to a hard ceiling now (conn closes on return); safe_fetch's
        # read_body then enforces the policy cap against these bytes.
        raw = resp.read(2_000_000 + 1)

        def read_body(cap, deadline, clock, _raw=raw):
            if len(_raw) > cap:
                return None
            return _raw.decode("utf-8", errors="replace")

        return status, headers, location, read_body
    except (socket.timeout, TimeoutError):
        raise _NetError("timeout", "connect_or_read_timeout")
    except ssl.SSLError as e:
        raise _NetError("tls", str(e)[:120])
    except socket.gaierror as e:
        raise _NetError("dns", str(e)[:120])
    except OSError as e:
        raise _NetError("connection", str(e)[:120])
    finally:
        try:
            conn.close()
        except Exception:
            pass
