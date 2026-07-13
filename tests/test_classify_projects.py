"""Unit tests for classify_projects.py — detectors + orchestrator (offline)."""

import json

import classify_projects as cp

BUNDLE = cp.load_cfg_bundle()
WEBCFG = BUNDLE["webcfg"]
LIBCFG = BUNDLE["libcfg"]


# --------------------------------------------------------------------------- #
# Indicator matching
# --------------------------------------------------------------------------- #
def test_has_file_indicator_root_and_nested():
    files = {"next.config.js", "src/App.tsx", "packages/web/vite.config.ts"}
    assert cp.has_file_indicator(files, "next.config.js")
    assert cp.has_file_indicator(files, "src/App.tsx")
    assert cp.has_file_indicator(files, "vite.config.ts")     # nested, by basename
    assert not cp.has_file_indicator(files, "nuxt.config.ts")


def test_has_dir_indicator():
    files = {"pages/index.tsx", "src/routes/+page.svelte", "public/logo.png"}
    assert cp.has_dir_indicator(files, "pages/")
    assert cp.has_dir_indicator(files, "src/routes/")
    assert cp.has_dir_indicator(files, "public/")
    assert not cp.has_dir_indicator(files, "app/")


# --------------------------------------------------------------------------- #
# Tech indicators
# --------------------------------------------------------------------------- #
def test_count_js_ts_files_excludes_vendored():
    files = {"src/a.ts", "src/b.tsx", "src/c.js", "types/x.d.ts",
             "node_modules/react/index.js", "dist/bundle.js", "README.md"}
    # a.ts, b.tsx, c.js count; d.ts excluded; node_modules/dist excluded.
    assert cp.count_js_ts_files(files) == 3


def test_detect_tech_indicators():
    files = {".github/workflows/ci.yml", "Dockerfile", "tsconfig.json",
             "src/index.ts", "package.json"}
    t = cp.detect_tech_indicators(files)
    assert t == {"github_actions_present": True, "docker_present": True,
                 "typescript_present": True, "has_package_json": True}


def test_detect_tech_indicators_negatives():
    files = {"index.js", "README.md"}
    t = cp.detect_tech_indicators(files)
    assert not any([t["github_actions_present"], t["docker_present"],
                    t["typescript_present"]])
    assert t["has_package_json"] is False


# --------------------------------------------------------------------------- #
# Web-app detection + framework + application type
# --------------------------------------------------------------------------- #
def test_nextjs_is_web_app_fullstack():
    files = {"next.config.js", "package.json", "pages/index.tsx", "app/api/route.ts"}
    deps = {"next", "react", "react-dom"}
    web = cp.detect_web_app(files, deps, WEBCFG)
    assert web["is_web_app"] is True
    assert "next.config.js" in web["primary"]
    fw, meta = cp.detect_framework(web)
    assert fw == "next" and meta == "next"
    assert cp.detect_application_type(files, deps, web) == "fullstack_monolith"


def test_react_plus_express_is_fullstack():
    files = {"package.json", "src/App.jsx", "public/index.html", "server.js"}
    deps = {"react", "react-dom", "express"}
    web = cp.detect_web_app(files, deps, WEBCFG)
    assert web["is_web_app"] is True                 # primary indicator src/App.jsx
    assert cp.detect_application_type(files, deps, web) == "fullstack_monolith"


def test_react_plus_supabase_is_baas():
    files = {"package.json", "src/main.tsx", "public/favicon.ico"}
    deps = {"react", "react-dom", "@supabase/supabase-js"}
    web = cp.detect_web_app(files, deps, WEBCFG)
    assert cp.detect_application_type(files, deps, web) == "frontend_plus_baas"


def test_backend_only_is_api():
    files = {"package.json", "src/server.ts", "api/users.ts"}
    deps = {"express"}
    web = cp.detect_web_app(files, deps, WEBCFG)
    assert cp.detect_application_type(files, deps, web) == "backend_or_api"


def test_astro_is_frontend_only():
    files = {"astro.config.mjs", "package.json", "src/pages/index.astro"}
    deps = {"astro"}
    web = cp.detect_web_app(files, deps, WEBCFG)
    fw, meta = cp.detect_framework(web)
    assert meta == "astro"
    assert cp.detect_application_type(files, deps, web) == "frontend_only"


def test_plain_library_is_not_web_app():
    files = {"package.json", "src/index.ts", "dist/index.js", "README.md"}
    deps = {"typescript"}
    web = cp.detect_web_app(files, deps, WEBCFG)
    assert web["is_web_app"] is False


# --------------------------------------------------------------------------- #
# Library / CLI detection
# --------------------------------------------------------------------------- #
def test_library_cli_signals():
    assert cp.detect_library_or_cli({"bin": {"tool": "./cli.js"}}, False, LIBCFG)[0] is True
    pub = cp.detect_library_or_cli({"private": False, "main": "index.js"}, False, LIBCFG)
    assert pub[0] is True and "private_false_and_main_only" in pub[1]
    # A web app with a main field is NOT a library.
    assert cp.detect_library_or_cli({"main": "index.js"}, True, LIBCFG)[0] is False
    assert cp.detect_library_or_cli(None, False, LIBCFG)[0] is False


# --------------------------------------------------------------------------- #
# Manual-review flags from metadata text
# --------------------------------------------------------------------------- #
def test_review_flags_from_name_and_topics():
    vuln = cp.detect_review_flags({"repository_full_name": "acme/juice-shop-clone"},
                                  BUNDLE["vuln_terms"], BUNDLE["tutorial_terms"])
    assert "intentionally_vulnerable_or_security_lab" in vuln
    tut = cp.detect_review_flags({"repository_full_name": "x/y", "topics": ["tutorial"]},
                                 BUNDLE["vuln_terms"], BUNDLE["tutorial_terms"])
    assert "tutorial_or_example" in tut
    clean = cp.detect_review_flags({"repository_full_name": "acme/dashboard",
                                    "description": "a nice app"},
                                   BUNDLE["vuln_terms"], BUNDLE["tutorial_terms"])
    assert clean == []


# --------------------------------------------------------------------------- #
# classify_repo integration
# --------------------------------------------------------------------------- #
def test_classify_repo_integration():
    files = ["next.config.ts", "package.json", "app/page.tsx",
             ".github/workflows/ci.yml", "Dockerfile", "tsconfig.json"]
    pkg = json.dumps({"dependencies": {"next": "14", "react": "18", "react-dom": "18"}})
    rec = cp.classify_repo("octo/site", files, pkg, {"repository_full_name": "octo/site"}, BUNDLE)
    assert rec["status"] == "OK"
    assert rec["is_web_app"] is True
    assert rec["framework"] == "next"
    assert rec["application_type"] == "fullstack_monolith"
    assert rec["github_actions_present"] and rec["docker_present"] and rec["typescript_present"]
    assert rec["is_library_or_cli"] is False


# --------------------------------------------------------------------------- #
# Orchestrator: metadata gating, caching, read errors
# --------------------------------------------------------------------------- #
def _reader_for(trees):
    def _fn(full, branch, url):
        files, pkg = trees[full]
        return files, pkg
    return _fn


def test_classify_all_gates_caches_and_handles_errors(tmp_path):
    trees = {
        "octo/site": (["next.config.js", "package.json"],
                      json.dumps({"dependencies": {"next": "14"}})),
    }
    reader = _reader_for(trees)
    candidates = [
        {"repository_full_name": "octo/site"},
        {"repository_full_name": "octo/gone"},   # metadata not OK -> UNAVAILABLE
    ]
    metadata = {
        "octo/site": {"repository_full_name": "octo/site", "fetch_status": "OK",
                      "default_branch": "main", "repository_url": "https://github.com/octo/site"},
        "octo/gone": {"repository_full_name": "octo/gone", "fetch_status": "NOT_FOUND"},
    }
    analysis_dir = tmp_path / "cls"
    log = tmp_path / "log.jsonl"
    rows = cp.classify_all(candidates, metadata, analysis_dir, log, reader, BUNDLE)
    by = {r["repository_full_name"]: r for r in rows}
    assert by["octo/site"]["status"] == "OK" and by["octo/site"]["is_web_app"] is True
    assert by["octo/gone"]["status"] == "UNAVAILABLE"
    assert (analysis_dir / "octo__site.json").exists()

    # Cached second run returns the same rows without calling the reader.
    def boom(full, branch, url):
        raise AssertionError("must not re-read a cached classification")
    rows2 = cp.classify_all(candidates, metadata, analysis_dir, log, boom, BUNDLE)
    assert {r["repository_full_name"]: r["status"] for r in rows2} == \
        {"octo/site": "OK", "octo/gone": "UNAVAILABLE"}


def test_classify_all_records_read_error(tmp_path):
    def failing(full, branch, url):
        raise RuntimeError("clone failed")
    candidates = [{"repository_full_name": "octo/site"}]
    metadata = {"octo/site": {"repository_full_name": "octo/site",
                              "fetch_status": "OK", "default_branch": "main"}}
    rows = cp.classify_all(candidates, metadata, tmp_path / "cls",
                           tmp_path / "log.jsonl", failing, BUNDLE)
    assert rows[0]["status"] == "READ_ERROR"
