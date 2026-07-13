#!/usr/bin/env python3
"""
cleanup_repositories.py — remove cloned repositories after scanning.

Safely deletes the working-tree, history-mirror, and candidate clones under
repositories/ once results have been produced. Every deletion target is verified
to be INSIDE the repositories/ root before removal (defence against a crafted
path). Raw scanner output and all results are untouched.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path
from typing import Optional

try:
    from . import _common as common  # type: ignore
    from . import verify_claude_attribution as vca  # type: ignore
except Exception:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _common as common  # type: ignore
    import verify_claude_attribution as vca  # type: ignore

STUDY_ROOT = common.STUDY_ROOT


def safe_remove(target: Path, root: Path) -> tuple[bool, str]:
    """Remove `target` only if it resolves inside `root`. Returns (removed, reason)."""
    if not target.exists():
        return False, "absent"
    if not vca._is_within(root, target) or target.resolve() == root.resolve():
        return False, "refused_outside_or_root"
    shutil.rmtree(target, ignore_errors=True)
    return True, "removed"


def cleanup(repositories_root: Path, subdirs=("selected", "history", "candidates")) -> list[dict]:
    results = []
    for sub in subdirs:
        target = repositories_root / sub
        removed, reason = safe_remove(target, repositories_root)
        results.append({"path": str(target), "removed": removed, "reason": reason})
    return results


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Remove cloned repositories (cleanup).")
    p.add_argument("--yes", action="store_true", help="confirm deletion")
    args = p.parse_args(argv)

    cfg = common.load_study_config()
    repos_root = STUDY_ROOT / "repositories"
    if not args.yes:
        print(f"Would remove clones under {repos_root} (selected/history/candidates). "
              f"Re-run with --yes to confirm.")
        return 0

    results = cleanup(repos_root)
    for r in results:
        print(f"  {r['reason']:26} {r['path']}")
    print(f"Cleanup done. Raw scanner output + results are untouched.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
