#!/usr/bin/env python3
"""
_common.py — shared helpers for study scripts.

Small, dependency-light utilities used across the pipeline: atomic writes,
UTC timestamps, hashing, YAML loading, JSONL logging. Kept importable (no
side effects at import time) so unit tests can exercise the pure helpers.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

STUDY_ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIR = STUDY_ROOT / "config"


# --------------------------------------------------------------------------- #
# Time / hashing
# --------------------------------------------------------------------------- #
def iso_now() -> str:
    """Current UTC time as ISO-8601 with a trailing Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- #
# Filesystem (atomic writes; never leave a half-written file)
# --------------------------------------------------------------------------- #
def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def atomic_write_text(path: Path, text: str) -> None:
    path = Path(path)
    ensure_dir(path.parent)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def atomic_write_json(path: Path, obj: Any, *, indent: int = 2) -> None:
    atomic_write_text(Path(path), json.dumps(obj, indent=indent, ensure_ascii=False))


def read_json(path: Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def is_valid_json_file(path: Path) -> bool:
    """True if the file exists and parses as JSON (used for resumption)."""
    try:
        read_json(path)
        return True
    except Exception:
        return False


def append_jsonl(path: Path, record: dict) -> None:
    """Append one JSON record as a line (request/audit logging)."""
    path = Path(path)
    ensure_dir(path.parent)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
def load_yaml(path: Path) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def load_study_config() -> dict:
    return load_yaml(CONFIG_DIR / "study-config.yaml")


def config_bundle_hash() -> str:
    """Order-independent SHA-256 over ALL config files, so any frozen artifact,
    SCANNERS_READY marker, or pilot record is tied to the exact configuration."""
    parts = []
    for path in sorted(CONFIG_DIR.iterdir()):
        if path.is_file():
            parts.append(f"{path.name}:{sha256_hex(path.read_bytes())}")
    return sha256_hex("\n".join(parts))


def hash_dir(path: Path) -> Optional[str]:
    """Deterministic SHA-256 over a directory's file contents (relpath + hash),
    order-independent. Returns None if the directory is missing or empty."""
    path = Path(path)
    if not path.is_dir():
        return None
    parts = []
    for f in sorted(path.rglob("*")):
        if f.is_file():
            parts.append(f"{f.relative_to(path).as_posix()}:{sha256_hex(f.read_bytes())}")
    return sha256_hex("\n".join(parts)) if parts else None
