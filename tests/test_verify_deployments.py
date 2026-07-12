"""Unit tests for verify_deployments.py — availability classification + robots (offline)."""

import verify_deployments as vd
import _common as common

DCFG = common.load_yaml(common.CONFIG_DIR / "deployment-rules.yaml")


def _cls(result):
    return vd.classify_availability(result, DCFG)


# --------------------------------------------------------------------------- #
# Status classification
# --------------------------------------------------------------------------- #
def test_live_confirmed():
    r = _cls({"http_status": 200, "title": "My App", "body_snippet": "<h1>Dashboard</h1>"})
    assert r["deployment_status"] == "LIVE_CONFIRMED"
    assert r["availability_eligible"] is True
    assert r["exclusion_code"] is None


def test_dead_404_and_410():
    assert _cls({"http_status": 404, "body_snippet": ""})["deployment_status"] == "DEAD_404"
    d = _cls({"http_status": 410, "body_snippet": ""})
    assert d["deployment_status"] == "DEAD_410"
    assert d["exclusion_code"] == "EX_DEPLOYMENT_DEAD"


def test_server_error_and_login_and_protected():
    assert _cls({"http_status": 503, "body_snippet": ""})["deployment_status"] == "SERVER_ERROR"
    assert _cls({"http_status": 401, "body_snippet": ""})["deployment_status"] == "LIVE_LOGIN_REQUIRED"
    assert _cls({"http_status": 401, "body_snippet": ""})["availability_eligible"] is True
    prot = _cls({"http_status": 403, "body_snippet": ""})
    assert prot["deployment_status"] == "PROVIDER_PROTECTED"
    assert prot["availability_eligible"] is False


def test_error_page_signals_on_2xx():
    # A 200 that is really a provider "not found" / parked / placeholder page.
    assert _cls({"http_status": 200, "body_snippet": "There's nothing here."})["deployment_status"] == "DEAD_404"
    assert _cls({"http_status": 200, "body_snippet": "Coming soon!"})["deployment_status"] == "PLACEHOLDER"
    assert _cls({"http_status": 200, "body_snippet": "buy this domain"})["deployment_status"] == "PARKED_DOMAIN"
    # Heroku application error = deployed but degraded (still eligible).
    deg = _cls({"http_status": 200, "body_snippet": "Application Error"})
    assert deg["deployment_status"] == "LIVE_DEGRADED" and deg["availability_eligible"] is True


def test_network_errors():
    assert _cls({"error": "timeout"})["deployment_status"] == "TIMEOUT"
    assert _cls({"error": "dns"})["deployment_status"] == "DNS_FAILURE"
    assert _cls({"error": "tls"})["deployment_status"] == "TLS_FAILURE"
    assert _cls({"error": "robots"})["deployment_status"] == "UNKNOWN"


# --------------------------------------------------------------------------- #
# robots.txt respect
# --------------------------------------------------------------------------- #
def test_robots_allows():
    ua = "claude-deployed-security-study/0.1"
    assert vd.robots_allows(None, ua) is True                       # no robots -> allow
    assert vd.robots_allows("User-agent: *\nDisallow:", ua) is True  # empty disallow
    assert vd.robots_allows("User-agent: *\nDisallow: /", ua) is False
    # A rule for a different agent does not apply to us.
    assert vd.robots_allows("User-agent: Googlebot\nDisallow: /", ua) is True


# --------------------------------------------------------------------------- #
# Title / correspondence-signal extraction
# --------------------------------------------------------------------------- #
def test_extract_title_and_signals():
    assert vd.extract_title("<html><title>  Hello  World </title>") == "Hello World"
    assert vd.repo_link_found("see github.com/octo/site for source", "octo/site") is True
    assert vd.name_in_page("Welcome to My Site", "octo/my-site") is True
    assert vd.name_in_page("unrelated", "octo/my-site") is False


# --------------------------------------------------------------------------- #
# verify_one + orchestrator (injected http_fn)
# --------------------------------------------------------------------------- #
def test_verify_one_captures_signals():
    disc = {"primary_deployment_url": "https://app.example.com", "best_evidence_level": "B"}

    def http_fn(url):
        return {"http_status": 200, "final_url": url, "content_type": "text/html",
                "title": "My Site", "body_snippet": "<a href='github.com/octo/my-site'>source</a>"}

    rec = vd.verify_one("octo/my-site", disc, http_fn, DCFG)
    assert rec["deployment_status"] == "LIVE_CONFIRMED"
    assert rec["repo_link_found"] is True
    assert rec["name_in_page"] is True
    assert rec["checked_url"] == "https://app.example.com"


def test_verify_all_gates_and_caches(tmp_path):
    calls = {"n": 0}

    def http_fn(url):
        calls["n"] += 1
        return {"http_status": 200, "final_url": url, "title": "App", "body_snippet": "hi"}

    discovery = [
        {"repository_full_name": "o/live", "status": "OK", "has_deployment_url": True,
         "primary_deployment_url": "https://o-live.example.com", "best_evidence_level": "B"},
        {"repository_full_name": "o/nourl", "status": "OK", "has_deployment_url": False,
         "best_evidence_level": None},
    ]
    raw_dir = tmp_path / "dv"
    rows = vd.verify_all(discovery, raw_dir, tmp_path / "log.jsonl", http_fn, DCFG)
    by = {r["repository_full_name"]: r for r in rows}
    assert by["o/live"]["deployment_status"] == "LIVE_CONFIRMED"
    assert by["o/nourl"]["status"] == "NO_URL"
    assert calls["n"] == 1                                   # only the repo with a URL was checked

    def boom(url):
        raise AssertionError("must not re-check a cached deployment")
    vd.verify_all(discovery, raw_dir, tmp_path / "log.jsonl", boom, DCFG)
    assert calls["n"] == 1
