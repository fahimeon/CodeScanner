#!/usr/bin/env python3
"""
classify_projects.py — Phase 7 project classification.

For each candidate repository, determine the covariates the funnel and analysis
need: whether it is a web application, its framework / meta-framework, its
application type, and tech indicators (GitHub Actions, Docker, TypeScript). Also
flags library/CLI-only projects and repos that warrant MANUAL_REVIEW
(intentionally-vulnerable / security-lab / tutorial) — recorded, never
auto-excluded here (screening applies the codes).

Reads the repository FILE TREE and root package.json via git (`git ls-tree` /
`git show HEAD:package.json`) against the Phase 6 history clone — NO working-tree
checkout, NO code execution.

Design mirrors the earlier phases: pure detectors (file/dep heuristics) split
from an injectable `reader_fn`, unit-tested offline with synthetic trees.

Outputs:
  data/interim/classification/{owner__repo}.json   (per-repo, recomputable)
  data/interim/project-classification.{json,csv}   (aggregate)
"""

from __future__ import annotations

import argparse
import csv
import json
import os
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

# Not in config (kept local, documented): BaaS + serverless indicators.
BAAS_DEPENDENCIES = ["@supabase/supabase-js", "supabase", "firebase", "@firebase/app",
                     "@aws-amplify/core", "aws-amplify", "@pocketbase/js", "pocketbase"]
SERVERLESS_FILES = ["vercel.json", "netlify.toml", "serverless.yml", "serverless.yaml",
                    "wrangler.toml", "netlify/functions", "functions"]

JS_TS_SOURCE_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".cts", ".mts",
                     ".vue", ".svelte", ".astro"}
_EXCLUDED_DIR_SEGMENTS = ("node_modules/", "dist/", "build/", ".next/", ".nuxt/",
                          "vendor/", "out/", "coverage/", ".svelte-kit/")

CLASSIFICATION_FIELDS = [
    "repository_full_name",
    "status",                       # OK | UNAVAILABLE | READ_ERROR
    "is_web_app",
    "js_ts_file_count",
    "application_type",
    "framework",
    "meta_framework",
    "frontend_libs",
    "backend_libs",
    "web_app_primary_indicators",
    "web_app_secondary_indicators",
    "is_library_or_cli",
    "library_cli_reasons",
    "github_actions_present",
    "docker_present",
    "typescript_present",
    "has_package_json",
    "flagged_reasons",
]
_LIST_FIELDS = {"frontend_libs", "backend_libs", "web_app_primary_indicators",
                "web_app_secondary_indicators", "library_cli_reasons", "flagged_reasons"}


# =========================================================================== #
# PURE FUNCTIONS — file-tree / package.json heuristics
# =========================================================================== #
def _norm(path: str) -> str:
    p = path.replace("\\", "/")
    if p.startswith("./"):        # strip only a literal leading "./", not '.'/'/' chars
        p = p[2:]
    return p


def has_file_indicator(files: set[str], indicator: str) -> bool:
    """Match a file indicator either as an exact repo path or by basename anywhere."""
    ind = _norm(indicator)
    if ind in files:
        return True
    if "/" in ind:
        return any(p == ind or p.endswith("/" + ind) for p in files)
    return any(p == ind or p.rsplit("/", 1)[-1] == ind for p in files)


def has_dir_indicator(files: set[str], directory: str) -> bool:
    """Match a directory subtree indicator (e.g. 'pages/') at root or nested."""
    d = _norm(directory).rstrip("/")
    return any(p == d or p.startswith(d + "/") or (("/" + d + "/") in ("/" + p))
               for p in files)


def parse_package_json(text: Optional[str]) -> Optional[dict]:
    if not text or not text.strip():
        return None
    try:
        obj = json.loads(text)
    except Exception:
        return None
    return obj if isinstance(obj, dict) else None


def all_dependencies(pkg: Optional[dict]) -> set[str]:
    """Union of dependencies + devDependencies + peerDependencies + optional."""
    if not pkg:
        return set()
    names: set[str] = set()
    for field in ("dependencies", "devDependencies", "peerDependencies",
                  "optionalDependencies"):
        deps = pkg.get(field)
        if isinstance(deps, dict):
            names.update(deps.keys())
    return names


def _matched(deps: set[str], candidates: list[str]) -> list[str]:
    return [c for c in candidates if c in deps]


def count_js_ts_files(files: set[str]) -> int:
    """Number of JavaScript/TypeScript source files outside vendored/build trees.
    Used for STRICT JS/TS eligibility (measured presence, not just package.json)."""
    n = 0
    for p in files:
        pn = _norm(p)
        if any(seg in ("/" + pn) for seg in _EXCLUDED_DIR_SEGMENTS):
            continue
        base = pn.rsplit("/", 1)[-1]
        if base.endswith(".d.ts"):
            continue
        ext = os.path.splitext(base)[1].lower()
        if ext in JS_TS_SOURCE_EXTS:
            n += 1
    return n


def detect_tech_indicators(files: set[str]) -> dict:
    gha = any(p.startswith(".github/workflows/") and p.endswith((".yml", ".yaml"))
              for p in files)
    docker = any(
        p.rsplit("/", 1)[-1] in ("Dockerfile", "Containerfile",
                                  "docker-compose.yml", "docker-compose.yaml",
                                  "compose.yml", "compose.yaml")
        or p.rsplit("/", 1)[-1].startswith("Dockerfile.")
        for p in files
    )
    ts = ("tsconfig.json" in {p.rsplit("/", 1)[-1] for p in files}) or \
         any(p.endswith((".ts", ".tsx")) and not p.endswith(".d.ts") for p in files)
    has_pkg = "package.json" in {p.rsplit("/", 1)[-1] for p in files}
    return {"github_actions_present": gha, "docker_present": docker,
            "typescript_present": ts, "has_package_json": has_pkg}


def detect_web_app(files: set[str], deps: set[str], webcfg: dict) -> dict:
    primary = [ind for ind in webcfg.get("primary_indicators", [])
               if has_file_indicator(files, ind)]
    secondary = [d for d in webcfg.get("secondary_indicators_dirs", [])
                 if has_dir_indicator(files, d)]
    di = webcfg.get("dependency_indicators", {})
    frontend = _matched(deps, di.get("frontend", []))
    meta = _matched(deps, di.get("meta_framework", []))
    backend = _matched(deps, di.get("backend", []))
    has_pkg = "package.json" in {p.rsplit("/", 1)[-1] for p in files}
    has_web_dep = bool(frontend or meta or backend)
    # >=1 primary indicator OR (package.json AND >=1 secondary indicator AND a web dep).
    is_web_app = bool(primary) or (has_pkg and bool(secondary) and has_web_dep)
    return {"is_web_app": is_web_app, "primary": primary, "secondary": secondary,
            "frontend": frontend, "meta": meta, "backend": backend}


def detect_framework(web: dict) -> tuple[str, str]:
    """Return (framework, meta_framework). Meta-framework wins as the headline."""
    meta = web["meta"][0] if web["meta"] else ""
    if meta:
        return meta, meta
    if web["frontend"]:
        return web["frontend"][0], ""
    if web["backend"]:
        return web["backend"][0], ""
    return "none", ""


def detect_application_type(files: set[str], deps: set[str], web: dict) -> str:
    meta = set(web["meta"])
    frontend = bool(web["frontend"] or web["meta"])
    backend = bool(web["backend"]) or has_file_indicator(files, "server.js") \
        or has_file_indicator(files, "server.ts")
    baas = bool(_matched(deps, BAAS_DEPENDENCIES))
    serverless = any(has_file_indicator(files, f) or has_dir_indicator(files, f)
                     for f in SERVERLESS_FILES)

    if meta & {"next", "nuxt", "@remix-run/react", "@sveltejs/kit"}:
        return "fullstack_monolith"       # SSR/API-route frameworks
    if meta & {"astro", "gatsby"} and not backend:
        return "frontend_only"            # predominantly static site generators
    if frontend and backend:
        return "fullstack_monolith"
    if frontend and baas:
        return "frontend_plus_baas"
    if frontend and serverless:
        return "serverless_web"
    if frontend:
        return "frontend_only"
    if backend:
        return "backend_or_api"
    if serverless:
        return "serverless_web"
    return "unknown"


def detect_library_or_cli(pkg: Optional[dict], is_web_app: bool,
                          libcfg: list) -> tuple[bool, list[str]]:
    """Library/CLI signals from package.json (bin field, publishable main/exports)."""
    if not pkg:
        return False, []
    reasons: list[str] = []
    if pkg.get("bin"):
        reasons.append("has_bin_field")
    is_private = pkg.get("private") is True
    has_main_or_exports = ("main" in pkg) or ("exports" in pkg)
    if (not is_private) and has_main_or_exports and (not is_web_app):
        reasons.append("private_false_and_main_only")
    files_field = pkg.get("files")
    if isinstance(files_field, list) and files_field and \
            all(str(f).strip("./").split("/")[0] in ("dist", "lib", "build") for f in files_field):
        reasons.append("files_field_points_to_dist_only")
    return bool(reasons), reasons


def _text_signals(metadata: dict, terms: list[str]) -> list[str]:
    """Match name/topics/description text against a term list (case-insensitive)."""
    full = (metadata.get("repository_full_name") or "").lower()
    name = full.rsplit("/", 1)[-1]
    desc = (metadata.get("description") or "").lower()
    topics = " ".join(str(t).lower() for t in (metadata.get("topics") or []))
    hay = f"{name} {desc} {topics}"
    return sorted({t for t in terms if t.lower() in hay})


def detect_review_flags(metadata: dict, vuln_terms: list[str],
                        tutorial_terms: list[str]) -> list[str]:
    flags: list[str] = []
    if _text_signals(metadata, vuln_terms):
        flags.append("intentionally_vulnerable_or_security_lab")
    if _text_signals(metadata, tutorial_terms):
        flags.append("tutorial_or_example")
    return flags


def classify_repo(full_name: str, files: list[str], pkg_text: Optional[str],
                  metadata: dict, cfg_bundle: dict) -> dict:
    """Full per-repo classification from the file tree + package.json + metadata."""
    file_set = {_norm(p) for p in files}
    pkg = parse_package_json(pkg_text)
    deps = all_dependencies(pkg)

    tech = detect_tech_indicators(file_set)
    web = detect_web_app(file_set, deps, cfg_bundle["webcfg"])
    framework, meta_framework = detect_framework(web)
    app_type = detect_application_type(file_set, deps, web)
    is_lib, lib_reasons = detect_library_or_cli(pkg, web["is_web_app"],
                                                cfg_bundle["libcfg"])
    flags = detect_review_flags(metadata, cfg_bundle["vuln_terms"],
                                cfg_bundle["tutorial_terms"])

    return {
        "repository_full_name": full_name,
        "status": "OK",
        "is_web_app": web["is_web_app"],
        "js_ts_file_count": count_js_ts_files(file_set),
        "application_type": app_type,
        "framework": framework,
        "meta_framework": meta_framework,
        "frontend_libs": web["frontend"],
        "backend_libs": web["backend"],
        "web_app_primary_indicators": web["primary"],
        "web_app_secondary_indicators": web["secondary"],
        "is_library_or_cli": is_lib,
        "library_cli_reasons": lib_reasons,
        "github_actions_present": tech["github_actions_present"],
        "docker_present": tech["docker_present"],
        "typescript_present": tech["typescript_present"],
        "has_package_json": tech["has_package_json"],
        "flagged_reasons": flags,
    }


# =========================================================================== #
# CONFIG
# =========================================================================== #
def load_cfg_bundle() -> dict:
    inclusion = common.load_yaml(common.CONFIG_DIR / "inclusion-rules.yaml")
    exclusion = common.load_yaml(common.CONFIG_DIR / "exclusion-rules.yaml")
    return {
        "webcfg": inclusion.get("web_application_detection", {}),
        "libcfg": exclusion.get("project_type_exclusions", {})
                  .get("library_cli_signals_in_package_json", []),
        "vuln_terms": exclusion.get("intentionally_vulnerable_signals", {})
                      .get("name_or_topic_terms", []),
        "tutorial_terms": exclusion.get("tutorial_copy_signals", {})
                          .get("name_or_topic_terms", []),
    }


# =========================================================================== #
# WRITERS
# =========================================================================== #
def _csv_row(rec: dict) -> dict:
    row = dict(rec)
    for field in _LIST_FIELDS:
        val = row.get(field)
        if isinstance(val, list):
            row[field] = ";".join(str(v) for v in val)
    return row


def write_classification(records: list[dict], json_path: Path, csv_path: Path) -> None:
    common.atomic_write_json(json_path, records)
    common.ensure_dir(Path(csv_path).parent)
    tmp = Path(csv_path).with_suffix(".csv.tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CLASSIFICATION_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for rec in records:
            writer.writerow(_csv_row(rec))
    os.replace(tmp, csv_path)


# =========================================================================== #
# ORCHESTRATION (I/O; git injected as reader_fn for testability)
# =========================================================================== #
# reader_fn signature: (full_name, default_branch, url) -> (file_list, package_json_text)
ReaderFn = Callable[[str, Optional[str], str], tuple[list, Optional[str]]]


def classify_all(candidates: list[dict], metadata_by_name: dict[str, dict],
                 analysis_dir: Path, log_path: Path, reader_fn: ReaderFn,
                 cfg_bundle: dict) -> list[dict]:
    common.ensure_dir(analysis_dir)
    rows: list[dict] = []
    seen: set[str] = set()

    for cand in candidates:
        full = cand.get("repository_full_name")
        if not full or full in seen:
            continue
        seen.add(full)

        meta = metadata_by_name.get(full)
        if not meta or meta.get("fetch_status") != "OK":
            rec = {"repository_full_name": full, "status": "UNAVAILABLE"}
            rows.append(rec)
            _log(log_path, full, "UNAVAILABLE", None)
            continue

        analysis_file = analysis_dir / f"{vca._safe_name(full)}.json"
        if common.is_valid_json_file(analysis_file):
            rows.append(common.read_json(analysis_file))
            continue

        try:
            files, pkg_text = reader_fn(
                full, meta.get("default_branch"),
                meta.get("repository_url") or f"https://github.com/{full}")
            rec = classify_repo(full, files, pkg_text, meta, cfg_bundle)
        except Exception as exc:
            rec = {"repository_full_name": full, "status": "READ_ERROR"}
            _log(log_path, full, "READ_ERROR", f"{type(exc).__name__}: {exc}")
            rows.append(rec)
            continue

        common.atomic_write_json(analysis_file, rec)
        rows.append(rec)
        _log(log_path, full, rec["status"], None, is_web_app=rec.get("is_web_app"))

    return rows


def _log(log_path: Path, full: str, status: str, error: Optional[str],
         is_web_app=None) -> None:
    common.append_jsonl(log_path, {
        "ts": common.iso_now(), "repository_full_name": full,
        "status": status, "is_web_app": is_web_app, "error": error,
    })


# --------------------------------------------------------------------------- #
# Real git-backed reader (file tree + root package.json; no checkout)
# --------------------------------------------------------------------------- #
def make_git_reader_fn(git_path: str, clone_root: Path,
                       clone_timeout: int = 300) -> ReaderFn:
    common.ensure_dir(clone_root)
    hooks_dir = clone_root / ".empty-hooks"
    common.ensure_dir(hooks_dir)
    env = vca._git_env()

    def _run(args: list[str], timeout: int):
        import subprocess
        return subprocess.run([git_path, *args], capture_output=True, text=True,
                              timeout=timeout, check=False, env=env)

    def _fn(full_name: str, default_branch: Optional[str], url: str):
        dest = clone_root / vca._safe_name(full_name)
        if not vca._is_within(clone_root, dest):
            raise RuntimeError(f"refusing to operate outside clone root: {dest}")
        if not (dest / ".git").exists() and not (dest / "HEAD").exists():
            args = vca.build_clone_args(url, str(dest), str(hooks_dir), default_branch)
            proc = _run(args, clone_timeout)
            if proc.returncode != 0:
                raise RuntimeError(f"clone failed: {proc.stderr.strip()[:200]}")
        ls = _run(["-C", str(dest), "ls-tree", "-r", "HEAD", "--name-only"], 120)
        if ls.returncode != 0:
            raise RuntimeError(f"git ls-tree failed: {ls.stderr.strip()[:200]}")
        files = [ln for ln in ls.stdout.splitlines() if ln.strip()]
        show = _run(["-C", str(dest), "show", "HEAD:package.json"], 60)
        pkg_text = show.stdout if show.returncode == 0 else None
        return files, pkg_text

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
    parser = argparse.ArgumentParser(description="Classify project type / framework (Phase 7).")
    parser.add_argument("--control", action="store_true")
    args = parser.parse_args(argv)

    cfg = common.load_study_config()
    cfg_bundle = load_cfg_bundle()
    interim = STUDY_ROOT / cfg["paths"]["interim"]

    if args.control:
        candidates_path = interim / "control" / "control-candidate-repositories.json"
        metadata_path = interim / "control" / "repository-metadata.json"
        analysis_dir = interim / "control" / "classification"
        out_json = interim / "control" / "project-classification.json"
        out_csv = interim / "control" / "project-classification.csv"
        log_path = STUDY_ROOT / cfg["paths"]["logs"] / "classify_projects_control.jsonl"
        key = "repo_full_name"
    else:
        candidates_path = interim / "claude-candidate-repositories.json"
        metadata_path = interim / "repository-metadata.json"
        analysis_dir = interim / "classification"
        out_json = interim / "project-classification.json"
        out_csv = interim / "project-classification.csv"
        log_path = STUDY_ROOT / cfg["paths"]["logs"] / "classify_projects.jsonl"
        key = "repository_full_name"

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
    if git is None:
        print("ERROR: git not found on PATH.", file=sys.stderr)
        return 2
    scanner_cfg = common.load_yaml(common.CONFIG_DIR / "scanner-config.yaml")
    clone_timeout = int(scanner_cfg.get("clone", {}).get("limits", {})
                        .get("clone_timeout_seconds", 300))
    clone_root = STUDY_ROOT / cfg["paths"]["candidates_clone"] / "history"
    reader_fn = make_git_reader_fn(git, clone_root, clone_timeout)

    rows = classify_all(candidates, metadata_by_name, analysis_dir, log_path,
                        reader_fn, cfg_bundle)
    write_classification(rows, out_json, out_csv)

    from collections import Counter
    web = sum(1 for r in rows if r.get("is_web_app"))
    types = Counter(r.get("application_type") for r in rows if r.get("status") == "OK")
    print(f"Classified {len(rows)} repositories -> {out_csv}")
    print(f"  web apps: {web}; application types: {dict(types)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
