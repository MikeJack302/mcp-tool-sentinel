"""Snapshot and policy configuration loading."""

from __future__ import annotations

from dataclasses import dataclass, fields
import json
from pathlib import Path
from typing import Any


MAX_JSON_BYTES = 10_000_000


@dataclass(frozen=True)
class Policy:
    allowed_protocol_versions: tuple[str, ...] = ("2026-07-28", "2025-11-25")
    allowed_schema_dialects: tuple[str, ...] = (
        "https://json-schema.org/draft/2020-12/schema",
        "http://json-schema.org/draft-07/schema#",
    )
    allowed_header_names: tuple[str, ...] = ()
    allow_external_refs: bool = False
    allow_new_tools: bool = False
    require_descriptions: bool = True
    require_annotations: bool = True
    require_output_schema: bool = False
    require_closed_input_schema: bool = True
    block_prompt_injection: bool = True
    max_tools: int = 50
    max_description_chars: int = 2000
    max_schema_depth: int = 32
    max_subschemas: int = 500

    @classmethod
    def from_dict(cls, value: Any) -> "Policy":
        if not isinstance(value, dict):
            raise ValueError("policy must be an object")
        names = {item.name for item in fields(cls)}
        unknown = sorted(set(value) - names)
        if unknown:
            raise ValueError("policy has unknown fields: " + ", ".join(unknown))
        converted = dict(value)
        tuple_fields = {"allowed_protocol_versions", "allowed_schema_dialects", "allowed_header_names"}
        for name in tuple_fields & set(converted):
            item = converted[name]
            if not isinstance(item, list) or not all(isinstance(entry, str) and entry.strip() for entry in item):
                raise ValueError(f"policy.{name} must be a list of non-empty strings")
            converted[name] = tuple(entry.strip() for entry in item)
        try:
            result = cls(**converted)
        except TypeError as exc:
            raise ValueError(f"policy: {exc}") from exc
        result.validate()
        return result

    def validate(self) -> None:
        for name in ("allowed_protocol_versions", "allowed_schema_dialects", "allowed_header_names"):
            value = getattr(self, name)
            if not isinstance(value, tuple) or not all(isinstance(item, str) and item for item in value):
                raise ValueError(f"policy.{name} must be a tuple of non-empty strings")
            folded = [item.casefold() for item in value]
            if len(folded) != len(set(folded)):
                raise ValueError(f"policy.{name} must not contain case-insensitive duplicates")
        for name in ("allowed_protocol_versions", "allowed_schema_dialects"):
            if not getattr(self, name):
                raise ValueError(f"policy.{name} must not be empty")
        for name in (
            "allow_external_refs", "allow_new_tools", "require_descriptions", "require_annotations",
            "require_output_schema", "require_closed_input_schema", "block_prompt_injection",
        ):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"policy.{name} must be boolean")
        for name in ("max_tools", "max_description_chars", "max_schema_depth", "max_subschemas"):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise ValueError(f"policy.{name} must be a positive integer")


def load_json(path: str | Path) -> Any:
    try:
        raw = Path(path).read_bytes()
        if len(raw) > MAX_JSON_BYTES:
            raise ValueError(f"{path}: JSON file exceeds {MAX_JSON_BYTES} bytes")
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object,
                          parse_constant=_reject_constant)
    except UnicodeDecodeError as exc:
        raise ValueError(f"{path}: JSON file is not valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}") from exc


def load_policy(path: str | Path) -> Policy:
    return Policy.from_dict(load_json(path))


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError(f"non-finite JSON number {value!r} is not allowed")
