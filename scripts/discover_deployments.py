#!/usr/bin/env python3
"""
discover_deployments.py — Phase 9-10 deployment URL discovery.

Discovers CANDIDATE public deployment URLs for each repository and assigns an
evidence level (A-D) and provider tag. This phase is DISCOVERY ONLY — it never
contacts the deployment site (that is Phase 11-13, non-invasive). It reads:
  * GitHub deployments API + Pages API (via gh; that is GitHub, not the app),
  * the repository homepage / description (from Phase 4 metadata),
  * repo files via git (README live-links, CNAME, deploy workflows, hosting configs).

Evidence levels (deployment-rules.yaml): A GitHub-deployment / production env URL;
B repository homepage or confirmed Pages URL; C README-labelled live link; D
supporting configuration only (never sufficient for inclusion alone).

Deployment URLs are PRIVATE (never published): the per-repo + aggregate outputs
go under data/private/. A URL-free summary (counts by level/provider) goes to
data/interim/.

Design mirrors earlier phases: pure discovery logic split from injectable
`reader_fn` (git) and `gh_fn` (deployments/pages), unit-tested offline.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
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

# Discovery source -> evidence level. A/B/C are inclusion-eligible; D is supporting.
SOURCE_EVIDENCE = {
    "github_deployments_api": "A",
    "production_environment_url": "A",
    "repository_homepage_field": "B",
    "github_pages_config": "B",
    "readme_labelled_live_link": "C",
    "repository_description": "D",
    "deploy_workflow_urls": "D",
    "cname_file": "D",
    "hosting_config_files": "D",
    "project_documentation": "D",
}
_LEVEL_RANK = {"A": 3, "B": 2, "C": 1, "D": 0}

HOSTING_CONFIG_BASENAMES = {"vercel.json", "netlify.toml", "render.yaml",
                            "wrangler.toml", "firebase.json"}

URL_RE = re.compile(r"https?://[^\s<>()\[\]\"']+", re.IGNORECASE)
MD_LINK_RE = re.compile(r"\[([^\]]+)\]\((https?://[^)\s]+)\)")

DISCOVERY_FIELDS = [
    "repository_full_name",
    "status",                    # OK | UNAVAILABLE | READ_ERROR
    "has_deployment_url",
    "best_evidence_level",
    "primary_deployment_url",
    "primary_provider",
    "candidate_count",
    "deployment_candidates",     # JSON list of {url, source, evidence_level, provider}
]
# Non-URL public summary columns (safe to share).
SUMMARY_FIELDS = ["repository_full_name", "status", "has_deployment_url",
                  "best_evidence_level", "primary_provider", "candidate_count"]


# =========================================================================== #
# PURE FUNCTIONS
# =========================================================================== #
def extract_urls(text: Optional[str]) -> list[str]:
    if not text:
        return []
    return [u.rstrip('.,);]"\'') for u in URL_RE.findall(text)]


def classify_provider(url: str, providers: dict) -> str:
    host = url.split("//", 1)[-1].split("/", 1)[0].split("@")[-1].split(":")[0].lower()
    for tag, suffixes in providers.items():
        for suf in suffixes or []:
            if host == suf or host.endswith("." + suf):
                return tag
    return "custom_or_unknown"


def source_evidence(source: str) -> str:
    return SOURCE_EVIDENCE.get(source, "D")


def parse_readme_live_links(readme: Optional[str], labels: list[str]) -> list[str]:
    """URLs from a README that are explicitly labelled as a live/demo/production link."""
    if not readme:
        return []
    labels_l = [l.lower() for l in labels]
    found: list[str] = []
    # Markdown links whose link text contains a label.
    for text, url in MD_LINK_RE.findall(readme):
        if any(l in text.lower() for l in labels_l):
            found.append(url)
    # Bare URLs whose same-line preceding text contains a label.
    for line in readme.splitlines():
        low = line.lower()
        if not any(l in low for l in labels_l):
            continue
        for m in URL_RE.finditer(line):
            before = low[:m.start()]
            if any(l in before for l in labels_l):
                found.append(m.group(0).rstrip('.,);]"\''))
    # De-dup preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for u in found:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _find_readme(contents: dict) -> Optional[str]:
    for path, text in contents.items():
        base = path.rsplit("/", 1)[-1].lower()
        if base in ("readme.md", "readme.mdx", "readme.markdown", "readme.rst",
                    "readme.txt", "readme"):
            return text
    return None


def dedup_candidates(candidates: list[dict]) -> list[dict]:
    """One entry per URL, keeping the highest-evidence discovery source."""
    best: dict[str, dict] = {}
    for c in candidates:
        url = c["url"]
        if url not in best or _LEVEL_RANK[c["evidence_level"]] > _LEVEL_RANK[best[url]["evidence_level"]]:
            best[url] = c
    return sorted(best.values(),
                  key=lambda c: (-_LEVEL_RANK[c["evidence_level"]], c["url"]))


def discover_for_repo(full_name: str, meta: dict, files: list[str], contents: dict,
                      gh_data: dict, providers: dict, labels: list[str]) -> dict:
    """Build the deployment-candidate record from all discovery sources."""
    raw: list[dict] = []

    def add(url: Optional[str], source: str, **extra) -> None:
        if not url:
            return
        url = url.strip().rstrip('.,);]"\'')
        if not url.lower().startswith(("http://", "https://")):
            return
        cand = {"url": url, "source": source,
                "evidence_level": source_evidence(source),
                "provider": classify_provider(url, providers)}
        cand.update({k: v for k, v in extra.items() if v is not None})
        raw.append(cand)

    # GitHub deployments API (retain deployment sha/ref/environment/timestamps).
    for dep in gh_data.get("deployments", []) or []:
        env = (dep.get("environment") or "").lower()
        for st in dep.get("statuses", []) or []:
            if st.get("state") == "success" and st.get("environment_url"):
                src = "production_environment_url" if ("prod" in env or env == "") \
                    else "github_deployments_api"
                add(st["environment_url"], src,
                    deployment_sha=dep.get("sha"), deployment_ref=dep.get("ref"),
                    deployment_environment=dep.get("environment"),
                    status_created_at=st.get("created_at"), url_source=src)
    # GitHub Pages.
    pages = gh_data.get("pages") or {}
    if isinstance(pages, dict) and pages.get("html_url"):
        add(pages["html_url"], "github_pages_config")
    # Repository homepage / description (from metadata).
    add(meta.get("homepage"), "repository_homepage_field")
    for u in extract_urls(meta.get("description")):
        add(u, "repository_description")
    # README-labelled live links.
    for u in parse_readme_live_links(_find_readme(contents), labels):
        add(u, "readme_labelled_live_link")
    # CNAME custom domain.
    for path, text in contents.items():
        if path.rsplit("/", 1)[-1].upper() == "CNAME" and text and text.strip():
            domain = text.strip().splitlines()[0].strip()
            if domain and "." in domain and " " not in domain:
                add(f"https://{domain}", "cname_file")
    # Deploy workflows + hosting configs (supporting).
    for path, text in contents.items():
        base = path.rsplit("/", 1)[-1]
        if path.startswith(".github/workflows/") and "deploy" in path.lower():
            for u in extract_urls(text):
                add(u, "deploy_workflow_urls")
        if base in HOSTING_CONFIG_BASENAMES:
            for u in extract_urls(text):
                add(u, "hosting_config_files")

    candidates = dedup_candidates(raw)
    best = candidates[0] if candidates else None
    return {
        "repository_full_name": full_name,
        "status": "OK",
        "has_deployment_url": bool(candidates),
        "best_evidence_level": best["evidence_level"] if best else None,
        "primary_deployment_url": best["url"] if best else None,
        "primary_provider": best["provider"] if best else None,
        # Deployment commit metadata (usually only present for Level-A candidates).
        "primary_deployment_sha": best.get("deployment_sha") if best else None,
        "primary_deployment_ref": best.get("deployment_ref") if best else None,
        "primary_deployment_environment": best.get("deployment_environment") if best else None,
        "candidate_count": len(candidates),
        "deployment_candidates": candidates,
    }


# =========================================================================== #
# WRITERS
# =========================================================================== #
def _private_row(rec: dict) -> dict:
    row = dict(rec)
    row["deployment_candidates"] = json.dumps(rec.get("deployment_candidates", []),
                                              separators=(",", ":"), ensure_ascii=False)
    return row


def write_discovery(records: list[dict], private_json: Path, private_csv: Path,
                    summary_csv: Path) -> None:
    # PRIVATE outputs (contain URLs) — never published.
    common.atomic_write_json(private_json, records)
    common.ensure_dir(private_csv.parent)
    tmp = private_csv.with_suffix(".csv.tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=DISCOVERY_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for rec in records:
            writer.writerow(_private_row(rec))
    os.replace(tmp, private_csv)
    # Non-URL summary (safe to share).
    common.ensure_dir(summary_csv.parent)
    tmp2 = summary_csv.with_suffix(".csv.tmp")
    with tmp2.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=SUMMARY_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for rec in records:
            writer.writerow(rec)
    os.replace(tmp2, summary_csv)


# =========================================================================== #
# ORCHESTRATION (I/O; git + gh injected for testability)
# =========================================================================== #
ReaderFn = Callable[[str, Optional[str], str], tuple[list, dict]]  # -> (files, contents)
GhFn = Callable[[str], dict]                                       # -> {deployments, pages}


def discover_all(candidates: list[dict], metadata_by_name: dict[str, dict],
                 raw_dir: Path, log_path: Path, reader_fn: ReaderFn, gh_fn: GhFn,
                 providers: dict, labels: list[str]) -> list[dict]:
    common.ensure_dir(raw_dir)
    rows: list[dict] = []
    seen: set[str] = set()

    for cand in candidates:
        full = cand.get("repository_full_name")
        if not full or full in seen:
            continue
        seen.add(full)

        meta = metadata_by_name.get(full)
        if not meta or meta.get("fetch_status") != "OK":
            rows.append({"repository_full_name": full, "status": "UNAVAILABLE"})
            _log(log_path, full, "UNAVAILABLE", None)
            continue

        cache = raw_dir / f"{vca._safe_name(full)}.json"
        if common.is_valid_json_file(cache):
            rows.append(common.read_json(cache))
            continue

        try:
            files, contents = reader_fn(
                full, meta.get("default_branch"),
                meta.get("repository_url") or f"https://github.com/{full}")
            gh_data = gh_fn(full)
            rec = discover_for_repo(full, meta, files, contents, gh_data, providers, labels)
        except Exception as exc:
            rec = {"repository_full_name": full, "status": "READ_ERROR"}
            _log(log_path, full, "READ_ERROR", f"{type(exc).__name__}: {exc}")
            rows.append(rec)
            continue

        common.atomic_write_json(cache, rec)
        rows.append(rec)
        _log(log_path, full, "OK", None, best=rec.get("best_evidence_level"))

    return rows


def _log(log_path: Path, full: str, status: str, error: Optional[str], best=None) -> None:
    common.append_jsonl(log_path, {
        "ts": common.iso_now(), "repository_full_name": full,
        "status": status, "best_evidence_level": best, "error": error,
    })


# --------------------------------------------------------------------------- #
# Real backends (git file reader + gh deployments/pages)
# --------------------------------------------------------------------------- #
DEPLOY_CONFIG_BASENAMES = HOSTING_CONFIG_BASENAMES | {"CNAME"}


def make_git_deploy_reader_fn(git_path: str, clone_root: Path,
                              clone_timeout: int = 300) -> ReaderFn:
    common.ensure_dir(clone_root)
    hooks_dir = clone_root / ".empty-hooks"
    common.ensure_dir(hooks_dir)
    env = vca._git_env()

    def _run(args, timeout):
        import subprocess
        return subprocess.run([git_path, *args], capture_output=True, text=True,
                              timeout=timeout, check=False, env=env)

    def _fn(full_name: str, default_branch: Optional[str], url: str):
        dest = clone_root / vca._safe_name(full_name)
        if not vca._is_within(clone_root, dest):
            raise RuntimeError(f"refusing to operate outside clone root: {dest}")
        if not (dest / ".git").exists() and not (dest / "HEAD").exists():
            args = vca.build_clone_args(url, str(dest), str(hooks_dir), default_branch)
            proc = _run([*args], clone_timeout)
            if proc.returncode != 0:
                raise RuntimeError(f"clone failed: {proc.stderr.strip()[:200]}")
        ls = _run(["-C", str(dest), "ls-tree", "-r", "HEAD", "--name-only"], 120)
        if ls.returncode != 0:
            raise RuntimeError(f"git ls-tree failed: {ls.stderr.strip()[:200]}")
        files = [ln for ln in ls.stdout.splitlines() if ln.strip()]

        wanted = []
        for p in files:
            base = p.rsplit("/", 1)[-1]
            if base.lower().startswith("readme") or base in DEPLOY_CONFIG_BASENAMES \
                    or (p.startswith(".github/workflows/") and "deploy" in p.lower()):
                wanted.append(p)
        contents: dict[str, str] = {}
        for p in wanted[:40]:              # bound the number of file reads
            show = _run(["-C", str(dest), "show", f"HEAD:{p}"], 60)
            if show.returncode == 0:
                contents[p] = show.stdout
        return files, contents

    return _fn


def make_gh_deploy_fn(gh_path: str, max_deployments: int = 5) -> GhFn:
    import subprocess

    def _api(path: str):
        proc = subprocess.run([gh_path, "api", path, "-H", "Accept: application/vnd.github+json"],
                              capture_output=True, text=True, timeout=60, check=False)
        if proc.returncode != 0:
            return None
        try:
            return json.loads(proc.stdout)
        except Exception:
            return None

    def _fn(full_name: str) -> dict:
        deployments = []
        deps = _api(f"repos/{full_name}/deployments?per_page={max_deployments}")
        for dep in (deps or [])[:max_deployments]:
            dep_id = dep.get("id")
            statuses = _api(f"repos/{full_name}/deployments/{dep_id}/statuses?per_page=10") or []
            deployments.append({"environment": dep.get("environment"), "statuses": statuses})
        pages = _api(f"repos/{full_name}/pages") or {}
        return {"deployments": deployments, "pages": pages}

    return _fn


# =========================================================================== #
# main
# =========================================================================== #
def _load_metadata_index(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    return {r["repository_full_name"]: r for r in common.read_json(path)
            if isinstance(r, dict) and r.get("repository_full_name")}


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Discover deployment URLs (Phase 9-10).")
    parser.add_argument("--control", action="store_true")
    args = parser.parse_args(argv)

    cfg = common.load_study_config()
    deploy_cfg = common.load_yaml(common.CONFIG_DIR / "deployment-rules.yaml")
    providers = deploy_cfg.get("providers", {})
    labels = deploy_cfg.get("readme_live_link_labels", [])
    interim = STUDY_ROOT / cfg["paths"]["interim"]
    private = STUDY_ROOT / cfg["paths"]["private"]

    sub = "control" if args.control else "."
    base_interim = interim / "control" if args.control else interim
    base_private = private / "control" if args.control else private
    key = "repo_full_name" if args.control else "repository_full_name"
    candidates_path = base_interim / (
        "control-candidate-repositories.json" if args.control
        else "claude-candidate-repositories.json")
    metadata_path = base_interim / "repository-metadata.json"

    if not candidates_path.exists() or not metadata_path.exists():
        print("ERROR: need candidate + metadata tables. Run 'make merge' and 'make metadata' first.",
              file=sys.stderr)
        return 2

    raw_candidates = common.read_json(candidates_path)
    candidates = [{"repository_full_name": c.get(key) or c.get("repository_full_name")}
                  for c in raw_candidates]
    candidates = [c for c in candidates if c["repository_full_name"]]
    metadata_by_name = _load_metadata_index(metadata_path)

    git = vca.find_git()
    gh = _which_gh()
    if git is None or gh is None:
        print("ERROR: git and gh are both required on PATH.", file=sys.stderr)
        return 2
    scanner_cfg = common.load_yaml(common.CONFIG_DIR / "scanner-config.yaml")
    clone_timeout = int(scanner_cfg.get("clone", {}).get("limits", {})
                        .get("clone_timeout_seconds", 300))
    clone_root = STUDY_ROOT / cfg["paths"]["candidates_clone"] / "history"
    reader_fn = make_git_deploy_reader_fn(git, clone_root, clone_timeout)
    gh_fn = make_gh_deploy_fn(gh)

    raw_dir = base_private / "deployments"
    log_path = STUDY_ROOT / cfg["paths"]["logs"] / (
        "discover_deployments_control.jsonl" if args.control else "discover_deployments.jsonl")
    rows = discover_all(candidates, metadata_by_name, raw_dir, log_path,
                        reader_fn, gh_fn, providers, labels)

    write_discovery(rows,
                    base_private / "deployment-discovery.json",
                    base_private / "deployment-discovery.csv",
                    base_interim / "deployment-discovery-summary.csv")

    from collections import Counter
    with_url = sum(1 for r in rows if r.get("has_deployment_url"))
    levels = Counter(r.get("best_evidence_level") for r in rows if r.get("has_deployment_url"))
    print(f"Discovered deployment candidates for {len(rows)} repositories "
          f"(URLs kept private under data/private/).")
    print(f"  with >=1 candidate URL: {with_url}; best-evidence levels: {dict(levels)}")
    return 0


def _which_gh() -> Optional[str]:
    import shutil
    gh = shutil.which("gh")
    if gh:
        return gh
    win = Path(r"C:\Program Files\GitHub CLI\gh.exe")
    return str(win) if win.exists() else None


if __name__ == "__main__":
    raise SystemExit(main())
