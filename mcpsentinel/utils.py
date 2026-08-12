"""Canonicalization and untrusted-text helpers."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterator


SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.I),
    re.compile(r"\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)\s*[:=]\s*[^\s,;]{6,}", re.I),
    re.compile(r"\bAuthorization\s*:\s*(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{6,}", re.I),
)
INJECTION_PATTERNS = (
    re.compile(r"\bignore (?:all |any )?(?:previous|prior|system) (?:instructions?|prompts?|rules?)\b", re.I),
    re.compile(r"\b(?:reveal|print|exfiltrate|send|upload) (?:the )?(?:system prompt|secrets?|credentials?|tokens?|api keys?)\b", re.I),
    re.compile(r"\b(?:disable|bypass|override) (?:the )?(?:security|guardrails?|policy|approval)\b", re.I),
    re.compile(r"\byou are now (?:in )?(?:developer|system|admin|root) mode\b", re.I),
)
SENSITIVE_NAME_RE = re.compile(
    r"(?:password|passwd|secret|token|api[_-]?key|authorization|cookie|session|ssn|social[_-]?security|email|phone|pii)", re.I
)
DANGEROUS_TOOL_RE = re.compile(
    r"(?:delete|remove|drop|destroy|execute|exec|shell|command|write|update|payment|transfer|send|email|upload|publish|deploy)", re.I
)
DESTRUCTIVE_TOOL_RE = re.compile(r"(?:delete|remove|drop|destroy|erase|purge|wipe)", re.I)
OPEN_WORLD_TOOL_RE = re.compile(r"(?:web|fetch|http|search|send|email|payment|transfer|upload|publish|deploy)", re.I)


def fingerprint(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def walk_strings(value: Any, path: str = "$") -> Iterator[tuple[str, str]]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from walk_strings(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from walk_strings(item, f"{path}[{index}]")


def finding(rule_id: str, severity: str, location: str, message: str, *, category: str = "audit") -> dict[str, str]:
    return {"rule_id": rule_id, "severity": severity, "location": location, "message": message, "category": category}
