#!/usr/bin/env python3
"""
verify_deployments.py — Phase 11-13 non-invasive availability check.

Confirms a discovered deployment URL is reachable and classifies its status,
using ONLY a non-invasive HEAD (GET fallback) on the discovered app URL. This
NEVER logs in, submits forms, enumerates routes, sends payloads, crawls links,
executes page JavaScript, or downloads large assets (see deployment-rules.yaml
availability_check and README ethical restrictions). robots.txt is respected.

While it has the (bounded, capped) page content, it also captures the
non-invasive correspondence signals the match phase needs (does the page link
back to the repo, does the project name appear), so the raw body is never stored.

Deployment URLs / titles are PRIVATE -> data/private/. A URL-free status summary
-> data/interim/.

Design: pure classification (classify_availability / robots_allows /
correspondence signals) split from an injectable `http_fn`, unit-tested offline.
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from pathlib import Path
from typing import Callable, Optional

try:
    from . import _common as common  # type: ignore
    from . import verify_claude_attribution as vca  # type: ignore
except Exception:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _common as common  # type: ignore
    import verify_claude_attribution as vca  # type: ignore

STUDY_ROOT = common.STUDY_ROOT

# Provider error/placeholder/parked page signal -> deployment status.
ERROR_PAGE_STATUS = [
    ("domain for sale", "PARKED_DOMAIN"),
    ("buy this domain", "PARKED_DOMAIN"),
    ("coming soon", "PLACEHOLDER"),
    ("vercel - the frontend cloud", "PLACEHOLDER"),
    ("just a moment", "PROVIDER_PROTECTED"),           # bot-wall interstitial
    ("application error", "LIVE_DEGRADED"),            # Heroku: deployed but erroring
    ("welcome to nginx", "UNRELATED_SITE"),
    ("it works!", "UNRELATED_SITE"),
    ("deployment not found", "DEAD_404"),
    ("there's nothing here", "DEAD_404"),
    ("no such app", "DEAD_404"),
    ("site not found", "DEAD_404"),
    ("404: not_found", "DEAD_404"),
    ("this page could not be found", "DEAD_404"),
]

DEPLOY_VERIFY_FIELDS = [
    "repository_full_name",
    "status",                    # OK | UNAVAILABLE | NO_URL
    "checked_url",
    "best_evidence_level",
    "deployment_status",
    "availability_eligible",
    "exclusion_code",
    "http_status",
    "final_url",
    "content_type",
    "page_title",
    "repo_link_found",
    "name_in_page",
]
SUMMARY_FIELDS = ["repository_full_name", "status", "best_evidence_level",
                  "deployment_status", "availability_eligible", "exclusion_code",
                  "http_status", "repo_link_found", "name_in_page"]

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


# =========================================================================== #
# PURE FUNCTIONS
# =========================================================================== #
def robots_allows(robots_text: Optional[str], user_agent: str, path: str = "/") -> bool:
    """Minimal robots.txt check: does any applicable group Disallow `path`?
    Fail-open only when there is no robots.txt at all (None)."""
    if robots_text is None:
        return True
    ua_token = user_agent.split("/", 1)[0].lower()
    groups: list[tuple[list[str], list[str]]] = []
    agents: list[str] = []
    disallows: list[str] = []

    def _flush():
        if agents:
            groups.append((list(agents), list(disallows)))

    for line in robots_text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip().lower(), val.strip()
        if key == "user-agent":
            if disallows:            # new group starts after a rule block
                _flush()
                agents, disallows = [], []
            agents.append(val.lower())
        elif key == "disallow":
            disallows.append(val)
    _flush()

    applicable: list[str] = []
    for ua_list, dis in groups:
        if any(a == "*" or ua_token in a for a in ua_list):
            applicable.extend(dis)
    for rule in applicable:
        if rule == "":
            continue            # "Disallow:" (empty) allows everything
        if path.startswith(rule):
            return False
    return True


def _match_error_page(title_body: str) -> Optional[str]:
    low = title_body.lower()
    for signal, status in ERROR_PAGE_STATUS:
        if signal in low:
            return status
    return None


def _status_record(name: str, cfg: dict) -> dict:
    live = cfg["status_values"]["live_states"]
    exc = cfg["status_values"]["excluded_states"]
    if name in live:
        return {"deployment_status": name, "availability_eligible": True,
                "exclusion_code": None}
    e = exc.get(name, {})
    return {"deployment_status": name,
            "availability_eligible": bool(e.get("eligible", False)),
            "exclusion_code": e.get("code")}


def classify_availability(result: dict, cfg: dict) -> dict:
    """Map an http_fn result to a deployment status + eligibility + exclusion code."""
    error = result.get("error")
    if error == "timeout":
        return _status_record("TIMEOUT", cfg)
    if error == "dns":
        return _status_record("DNS_FAILURE", cfg)
    if error == "tls":
        return _status_record("TLS_FAILURE", cfg)
    if error == "robots":
        return _status_record("UNKNOWN", cfg)         # not verified; unverifiable
    if error:
        return _status_record("UNKNOWN", cfg)

    title_body = f"{result.get('title') or ''} {result.get('body_snippet') or ''}"
    sig = _match_error_page(title_body)
    if sig:
        return _status_record(sig, cfg)

    code = result.get("http_status")
    if code == 404:
        return _status_record("DEAD_404", cfg)
    if code == 410:
        return _status_record("DEAD_410", cfg)
    if code is not None and 500 <= code < 600:
        return _status_record("SERVER_ERROR", cfg)
    if code == 401:
        return _status_record("LIVE_LOGIN_REQUIRED", cfg)
    if code == 403:
        return _status_record("PROVIDER_PROTECTED", cfg)
    if code is not None and 200 <= code < 400:
        return _status_record("LIVE_CONFIRMED", cfg)
    return _status_record("UNKNOWN", cfg)


def extract_title(body: Optional[str]) -> str:
    if not body:
        return ""
    m = TITLE_RE.search(body)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200] if m else ""


def repo_link_found(body: Optional[str], full_name: str) -> bool:
    if not body:
        return False
    return f"github.com/{full_name}".lower() in body.lower()


def name_in_page(title_body: str, full_name: str) -> bool:
    """Does the repository name appear in the page (title or body)?"""
    name = full_name.rsplit("/", 1)[-1].lower()
    if not name:
        return False
    variants = {name, name.replace("-", " "), name.replace("_", " "),
                name.replace("-", ""), name.replace("_", "")}
    low = title_body.lower()
    return any(v and v in low for v in variants)


def verify_one(full_name: str, discovery: dict, http_fn, cfg: dict) -> dict:
    """Non-invasively check a repo's primary discovered URL and classify it."""
    url = discovery.get("primary_deployment_url")
    if not url:
        return {"repository_full_name": full_name, "status": "NO_URL",
                "best_evidence_level": discovery.get("best_evidence_level")}
    result = http_fn(url)
    cls = classify_availability(result, cfg)
    title = result.get("title") or extract_title(result.get("body_snippet"))
    title_body = f"{title} {result.get('body_snippet') or ''}"
    return {
        "repository_full_name": full_name,
        "status": "OK",
        "checked_url": url,
        "best_evidence_level": discovery.get("best_evidence_level"),
        "deployment_status": cls["deployment_status"],
        "availability_eligible": cls["availability_eligible"],
        "exclusion_code": cls["exclusion_code"],
        "http_status": result.get("http_status"),
        "final_url": result.get("final_url") or url,
        "content_type": result.get("content_type"),
        "page_title": title,
        "repo_link_found": repo_link_found(result.get("body_snippet"), full_name),
        "name_in_page": name_in_page(title_body, full_name),
    }


# =========================================================================== #
# WRITERS
# =========================================================================== #
def write_verification(records: list[dict], private_json: Path, private_csv: Path,
                       summary_csv: Path) -> None:
    common.atomic_write_json(private_json, records)
    _write_csv(private_csv, records, DEPLOY_VERIFY_FIELDS)
    _write_csv(summary_csv, records, SUMMARY_FIELDS)


def _write_csv(path: Path, records: list[dict], fields: list[str]) -> None:
    import os
    common.ensure_dir(path.parent)
    tmp = path.with_suffix(".csv.tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for rec in records:
            writer.writerow(rec)
    os.replace(tmp, path)


# =========================================================================== #
# ORCHESTRATION
# =========================================================================== #
HttpFn = Callable[[str], dict]


def verify_all(discovery_records: list[dict], raw_dir: Path, log_path: Path,
               http_fn: HttpFn, cfg: dict) -> list[dict]:
    common.ensure_dir(raw_dir)
    rows: list[dict] = []
    seen: set[str] = set()
    for disc in discovery_records:
        full = disc.get("repository_full_name")
        if not full or full in seen:
            continue
        seen.add(full)
        if disc.get("status") != "OK" or not disc.get("has_deployment_url"):
            rows.append({"repository_full_name": full,
                         "status": "NO_URL" if disc.get("status") == "OK" else "UNAVAILABLE",
                         "best_evidence_level": disc.get("best_evidence_level")})
            continue
        cache = raw_dir / f"{vca._safe_name(full)}.json"
        if common.is_valid_json_file(cache):
            rows.append(common.read_json(cache))
            continue
        rec = verify_one(full, disc, http_fn, cfg)
        common.atomic_write_json(cache, rec)
        rows.append(rec)
        common.append_jsonl(log_path, {
            "ts": common.iso_now(), "repository_full_name": full,
            "deployment_status": rec.get("deployment_status"),
            "http_status": rec.get("http_status")})
    return rows


# --------------------------------------------------------------------------- #
# Real non-invasive HTTP fetcher (stdlib urllib; HEAD then GET; capped)
# --------------------------------------------------------------------------- #
def make_http_fn(cfg: dict) -> HttpFn:
    import urllib.request
    import urllib.error
    import urllib.parse
    import socket

    ac = cfg["availability_check"]
    ua = ac["user_agent"]
    conn_timeout = ac.get("connection_timeout_seconds", 5)
    max_bytes = ac.get("maximum_response_bytes", 1_000_000)
    respect_robots = ac.get("respect_robots_txt", True)

    def _fetch(url: str, method: str) -> dict:
        req = urllib.request.Request(url, method=method, headers={"User-Agent": ua})
        try:
            with urllib.request.urlopen(req, timeout=conn_timeout) as resp:
                body = ""
                if method == "GET":
                    body = resp.read(max_bytes).decode("utf-8", errors="replace")
                return {"http_status": resp.status, "final_url": resp.geturl(),
                        "content_type": resp.headers.get("Content-Type", ""),
                        "body_snippet": body, "title": extract_title(body), "error": None}
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read(max_bytes).decode("utf-8", errors="replace")
            except Exception:
                pass
            return {"http_status": e.code, "final_url": url,
                    "content_type": e.headers.get("Content-Type", "") if e.headers else "",
                    "body_snippet": body, "title": extract_title(body), "error": None}
        except socket.timeout:
            return {"http_status": None, "final_url": url, "error": "timeout"}
        except urllib.error.URLError as e:
            reason = str(getattr(e, "reason", e)).lower()
            err = "dns" if ("name or service" in reason or "getaddrinfo" in reason) else \
                  "tls" if ("certificate" in reason or "ssl" in reason) else \
                  "timeout" if "timed out" in reason else "connection"
            return {"http_status": None, "final_url": url, "error": err}
        except Exception:
            return {"http_status": None, "final_url": url, "error": "connection"}

    def _robots_ok(url: str) -> bool:
        if not respect_robots:
            return True
        parts = urllib.parse.urlsplit(url)
        robots_url = urllib.parse.urlunsplit((parts.scheme, parts.netloc, "/robots.txt", "", ""))
        r = _fetch(robots_url, "GET")
        if r.get("error") or (r.get("http_status") or 0) >= 400:
            return True                     # no usable robots -> allow the single root check
        return robots_allows(r.get("body_snippet"), ua, parts.path or "/")

    def _fn(url: str) -> dict:
        if not _robots_ok(url):
            return {"http_status": None, "final_url": url, "error": "robots"}
        head = _fetch(url, "HEAD")
        # Fall back to GET when HEAD is unsupported or gave no useful signal.
        if head.get("error") or (head.get("http_status") in (405, 501)) or \
                (head.get("http_status") is None):
            return _fetch(url, "GET")
        # For a 2xx HEAD we still need body to classify error pages / correspondence.
        if 200 <= (head.get("http_status") or 0) < 400:
            return _fetch(url, "GET")
        return head

    return _fn


# =========================================================================== #
# main
# =========================================================================== #
def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Non-invasive deployment availability (Phase 11-13).")
    parser.add_argument("--control", action="store_true")
    args = parser.parse_args(argv)

    cfg = common.load_study_config()
    deploy_cfg = common.load_yaml(common.CONFIG_DIR / "deployment-rules.yaml")
    private = STUDY_ROOT / cfg["paths"]["private"]
    interim = STUDY_ROOT / cfg["paths"]["interim"]
    base_private = private / "control" if args.control else private
    base_interim = interim / "control" if args.control else interim

    discovery_path = base_private / "deployment-discovery.json"
    if not discovery_path.exists():
        print(f"ERROR: deployment discovery not found: {discovery_path}", file=sys.stderr)
        print("       Run 'make discover-deployments' first.", file=sys.stderr)
        return 2
    discovery_records = common.read_json(discovery_path)

    raw_dir = base_private / "deployment-verification"
    log_path = STUDY_ROOT / cfg["paths"]["logs"] / (
        "verify_deployments_control.jsonl" if args.control else "verify_deployments.jsonl")
    http_fn = make_http_fn(deploy_cfg)

    rows = verify_all(discovery_records, raw_dir, log_path, http_fn, deploy_cfg)
    write_verification(rows,
                       base_private / "deployment-verification.json",
                       base_private / "deployment-verification.csv",
                       base_interim / "deployment-verification-summary.csv")

    from collections import Counter
    statuses = Counter(r.get("deployment_status") for r in rows if r.get("status") == "OK")
    eligible = sum(1 for r in rows if r.get("availability_eligible"))
    print(f"Checked {len(rows)} deployments (non-invasive HEAD/GET on '/').")
    print(f"  availability-eligible: {eligible}; statuses: {dict(statuses)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
