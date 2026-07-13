"""Unit tests for net_safety.py — SSRF/redirect/deadline defences (fully synthetic).

No real network is ever contacted: the resolver, opener, clock, and throttle are
all injected fakes.
"""

import net_safety as ns


POLICY = ns.FetchPolicy(total_deadline_s=10.0, max_redirects=3, per_domain_per_minute=10)


# --------------------------------------------------------------------------- #
# IP classification
# --------------------------------------------------------------------------- #
def test_is_public_ip():
    assert ns.is_public_ip("8.8.8.8") is True
    assert ns.is_public_ip("2606:4700:4700::1111") is True
    for private in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1",
                    "169.254.1.1", "224.0.0.1", "0.0.0.0", "::1", "fe80::1",
                    "fc00::1", "::ffff:127.0.0.1"):   # ipv4-mapped loopback unwrapped
        assert ns.is_public_ip(private) is False, private
    assert ns.is_public_ip("not-an-ip") is False


# --------------------------------------------------------------------------- #
# URL validation (DNS-independent)
# --------------------------------------------------------------------------- #
def test_validate_url_rejects_dangerous_forms():
    bad = {
        "ftp://example.com": "scheme_not_allowed",
        "file:///etc/passwd": "scheme_not_allowed",
        "http://user:pw@example.com": "userinfo",
        "http://evil@example.com": "userinfo",
        "http://localhost/": "blocked_host",
        "http://foo.local/": "blocked_host",
        "http://127.0.0.1/": "non_public_ip_literal",
        "http://[::1]/": "non_public_ip_literal",
        "http://2130706433/": "non_public_ip_literal",   # decimal-integer 127.0.0.1
        "http://10.0.0.5/": "non_public_ip_literal",
    }
    for url, expect in bad.items():
        ok, reason, _ = ns.validate_url(url)
        assert ok is False and expect in reason, f"{url} -> {reason}"


def test_validate_url_accepts_public():
    ok, reason, parts = ns.validate_url("https://app.example.com/path")
    assert ok is True and reason is None and parts.hostname == "app.example.com"


def test_validate_resolved_rejects_any_private_address():
    ok, reason, _ = ns.validate_resolved("host", lambda h: ["8.8.8.8", "10.0.0.1"])
    assert ok is False and "non_public_resolved_ip" in reason
    ok, reason, ips = ns.validate_resolved("host", lambda h: ["93.184.216.34"])
    assert ok is True and ips == ["93.184.216.34"]
    ok, reason, _ = ns.validate_resolved("host", lambda h: [])
    assert ok is False and reason == "dns_no_records"


# --------------------------------------------------------------------------- #
# Fake opener/resolver harness
# --------------------------------------------------------------------------- #
def _opener(script):
    calls = []

    def opener(host, ip, port, scheme, method, path, timeout, ua):
        idx = len(calls)
        calls.append({"host": host, "ip": ip, "method": method, "path": path})
        r = script[idx] if idx < len(script) else script[-1]
        if r.get("oversize"):
            read_body = lambda cap, deadline, clock: None
        elif r.get("body") is not None:
            read_body = lambda cap, deadline, clock, b=r["body"]: b
        else:
            read_body = None
        return r["status"], r.get("headers", {}), r.get("location"), read_body

    opener.calls = calls
    return opener


# --------------------------------------------------------------------------- #
# Redirect safety
# --------------------------------------------------------------------------- #
def test_public_to_private_redirect_is_rejected():
    # First host public; it 302s to an internal host that resolves to a private IP.
    def resolver(host):
        return {"app.example.com": ["93.184.216.34"],
                "internal.example.com": ["169.254.169.254"]}[host]   # cloud metadata IP
    opener = _opener([{"status": 302, "location": "http://internal.example.com/"}])
    r = ns.safe_fetch("http://app.example.com/", POLICY, method="HEAD",
                      resolver=resolver, opener=opener)
    assert r.error == "rejected"
    assert "non_public_resolved_ip" in r.rejection_reason
    assert len(opener.calls) == 1                 # never connected to the internal host


def test_redirect_loop_hits_max():
    resolver = lambda h: ["93.184.216.34"]
    opener = _opener([{"status": 302, "location": "http://app.example.com/x"}])
    r = ns.safe_fetch("http://app.example.com/", POLICY, method="HEAD",
                      resolver=resolver, opener=opener)
    assert r.error == "rejected" and r.rejection_reason == "too_many_redirects"
    assert len(opener.calls) == POLICY.max_redirects + 1


def test_ipv6_public_ok_and_private_rejected():
    ok = ns.safe_fetch("https://v6.example.com/", POLICY, method="HEAD",
                       resolver=lambda h: ["2606:4700:4700::1111"],
                       opener=_opener([{"status": 200}]))
    assert ok.http_status == 200 and ok.error is None
    bad = ns.safe_fetch("https://v6.example.com/", POLICY, method="HEAD",
                        resolver=lambda h: ["::1"], opener=_opener([{"status": 200}]))
    assert bad.error == "rejected" and "non_public_resolved_ip" in bad.rejection_reason


def test_integer_ip_host_rejected_at_dns_stage():
    # If validate_url misses an odd literal, the resolver step still catches it.
    r = ns.safe_fetch("http://0x7f000001.example/", POLICY, method="HEAD",
                      resolver=lambda h: ["127.0.0.1"], opener=_opener([{"status": 200}]))
    assert r.error == "rejected" and "non_public_resolved_ip" in r.rejection_reason


# --------------------------------------------------------------------------- #
# DNS-rebinding: connection is pinned to the validated IP
# --------------------------------------------------------------------------- #
def test_connection_is_pinned_to_validated_ip():
    resolver = lambda h: ["93.184.216.34"]        # validated public IP
    opener = _opener([{"status": 200, "body": "<title>App</title>"}])
    r = ns.safe_fetch("https://app.example.com/", POLICY, method="GET",
                      resolver=resolver, opener=opener)
    assert r.http_status == 200
    # The opener was handed the pre-validated IP, not asked to re-resolve.
    assert opener.calls[0]["ip"] == "93.184.216.34"
    assert opener.calls[0]["host"] == "app.example.com"    # Host preserved for SNI/vhost


# --------------------------------------------------------------------------- #
# Body cap + total deadline
# --------------------------------------------------------------------------- #
def test_oversized_body_rejected():
    r = ns.safe_fetch("https://app.example.com/", POLICY, method="GET",
                      resolver=lambda h: ["93.184.216.34"],
                      opener=_opener([{"status": 200, "oversize": True}]))
    assert r.error == "too_large" and r.rejection_reason == "body_exceeded_cap"


def test_total_deadline_enforced_across_redirects():
    ticks = iter([0.0, 0.0, 5.0, 11.0])            # last tick is past the 10s deadline
    clock = lambda: next(ticks)
    opener = _opener([{"status": 302, "location": "https://app.example.com/next"}])
    r = ns.safe_fetch("https://app.example.com/", POLICY, method="HEAD",
                      resolver=lambda h: ["93.184.216.34"], opener=opener, clock=clock)
    assert r.error == "deadline" and r.rejection_reason == "total_deadline_exceeded"


# --------------------------------------------------------------------------- #
# Per-domain throttle
# --------------------------------------------------------------------------- #
def test_domain_throttle_blocks_after_limit():
    t = ns.DomainThrottle(per_minute=2, clock=lambda: 0.0)
    assert t.allow("d.com") and t.allow("d.com")
    assert t.allow("d.com") is False              # third within the window

    throttled = ns.DomainThrottle(per_minute=1, clock=lambda: 0.0)
    throttled.allow("app.example.com")            # exhaust the budget
    r = ns.safe_fetch("https://app.example.com/", POLICY, method="HEAD",
                      resolver=lambda h: ["93.184.216.34"],
                      opener=_opener([{"status": 200}]), throttle=throttled)
    assert r.error == "rejected" and r.rejection_reason == "domain_rate_limited"
