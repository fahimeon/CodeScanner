#!/usr/bin/env python3
"""
redaction.py — detect + redact secret-like tokens from logs, reports, and gate
inputs. Never let a plaintext secret reach any stored artifact (audit #19).

Pure and dependency-free; unit-tested with synthetic (fake) secrets only.
"""

from __future__ import annotations

import re

REDACTED = "REDACTED"

# Pattern name -> regex for common secret shapes. Deliberately conservative.
SECRET_PATTERNS = {
    "aws_access_key_id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bgh[posru]_[A-Za-z0-9]{20,}\b"),
    "github_fine_grained": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "openai_key": re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
    "private_key_block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
    "generic_bearer": re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-\._~\+/]{20,}=*"),
}

# Keys whose VALUES must always be redacted regardless of shape (structured data).
SENSITIVE_KEYS = {"secret", "password", "passwd", "token", "api_key", "apikey",
                  "access_key", "private_key", "authorization", "auth", "credential"}


def find_secrets(text: str) -> list[str]:
    if not text:
        return []
    hits = []
    for name, rx in SECRET_PATTERNS.items():
        if rx.search(text):
            hits.append(name)
    return hits


def contains_unredacted_secret(text: str) -> bool:
    """True if a secret-like token is present in a form that is NOT already redacted."""
    return bool(find_secrets(text))


def redact_text(text: str) -> str:
    if not text:
        return text
    out = text
    for rx in SECRET_PATTERNS.values():
        out = rx.sub(REDACTED, out)
    return out


def redact_record(obj):
    """Recursively redact sensitive VALUES (by key) and secret-like strings."""
    if isinstance(obj, dict):
        return {k: (REDACTED if (isinstance(k, str) and k.lower() in SENSITIVE_KEYS
                                 and isinstance(v, str) and v)
                    else redact_record(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_record(v) for v in obj]
    if isinstance(obj, str):
        return redact_text(obj)
    return obj
