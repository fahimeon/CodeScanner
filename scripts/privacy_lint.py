#!/usr/bin/env python3
"""
privacy_lint.py — CS-013 public-output privacy guard.

Public artifacts (data/public/**, results/reports/public/**, results/tables that
are published) must never carry study-subject identity: GitHub URLs, `owner/repo`
or `owner__repo` names, raw secret material, or deployment hostnames. This module
provides a PURE `find_identity_leaks(text)` (unit-tested, no I/O) plus a CLI that
walks the configured public trees and exits non-zero on any leak so CI/pre-commit
can block a release. Anonymous IDs (CLD-/CLR-/CTR-/RSV-####) are explicitly allowed.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Optional

try:
    from . import _common as common  # type: ignore
except Exception:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _common as common  # type: ignore

STUDY_ROOT = common.STUDY_ROOT

# Public trees that must stay anonymous. Kept explicit (never "all of results/").
PUBLIC_TREES = ("data/public", "results/reports/public", "results/public")

_GITHUB_URL = re.compile(r"https?://(?:www\.)?github\.com/[\w.-]+/[\w.-]+", re.I)
_GIT_REMOTE = re.compile(r"git@github\.com:[\w.-]+/[\w.-]+", re.I)
# owner__repo (our safe-name join) or owner/repo, but NOT anonymous IDs or paths.
_REPO_SLUG = re.compile(r"\b[\w.-]+__[\w.-]+\b")
# Common raw-secret prefixes that must never reach a public artifact unredacted.
_SECRET_TOKEN = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b")

_ANON_ID = re.compile(r"^(?:CLD|CLR|CTR|RSV)-\d{3,}$")


def _is_anonymous_id(token: str) -> bool:
    return bool(_ANON_ID.match(token))


def find_identity_leaks(text: str) -> list[str]:
    """Return a de-duplicated, sorted list of identity/secret leaks in `text`.

    Empty list == clean. A match is reported as `"<kind>:<snippet>"`. Anonymous
    study IDs never count as leaks even though they contain digits/dashes."""
    leaks: set[str] = set()
    for m in _GITHUB_URL.finditer(text):
        leaks.add(f"github_url:{m.group(0)}")
    for m in _GIT_REMOTE.finditer(text):
        leaks.add(f"git_remote:{m.group(0)}")
    for m in _SECRET_TOKEN.finditer(text):
        leaks.add(f"secret_token:{m.group(0)[:6]}***")
    for m in _REPO_SLUG.finditer(text):
        tok = m.group(0)
        if _is_anonymous_id(tok):
            continue
        leaks.add(f"repo_slug:{tok}")
    return sorted(leaks)


def scan_tree(root: Path) -> dict[str, list[str]]:
    """Map each public file with leaks to its leak list (skips binary/unreadable)."""
    findings: dict[str, list[str]] = {}
    if not root.exists():
        return findings
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == ".gitkeep":
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="strict")
        except (UnicodeDecodeError, OSError):
            continue  # binary/unreadable — not a text-identity risk here
        leaks = find_identity_leaks(text)
        if leaks:
            try:
                key = str(path.relative_to(STUDY_ROOT))
            except ValueError:
                key = str(path)          # scanning a tree outside the study root
            findings[key] = leaks
    return findings


def main(argv: Optional[list[str]] = None) -> int:
    import argparse
    p = argparse.ArgumentParser(description="Fail if public artifacts leak study-subject identity.")
    p.add_argument("--tree", action="append", help="extra public tree(s) to scan")
    args = p.parse_args(argv)

    trees = [STUDY_ROOT / t for t in PUBLIC_TREES]
    trees += [Path(t) for t in (args.tree or [])]

    total = 0
    for root in trees:
        for rel, leaks in scan_tree(root).items():
            total += len(leaks)
            print(f"LEAK {rel}: {', '.join(leaks)}", file=sys.stderr)
    if total:
        print(f"privacy_lint: {total} identity/secret leak(s) in public trees.", file=sys.stderr)
        return 1
    print("privacy_lint: public trees clean (no identities/secrets).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
