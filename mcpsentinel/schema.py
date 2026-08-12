"""Bounded JSON Schema inspection and security-oriented semantic diff."""

from __future__ import annotations

import json
import re
from typing import Any

from .model import Policy
from .utils import SENSITIVE_NAME_RE, finding


JSON_TYPES = {"null", "boolean", "object", "array", "number", "string", "integer"}
HEADER_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
SAFE_INTEGER = 9_007_199_254_740_991
SINGLE_SCHEMA_KEYS = {
    "items", "contains", "not", "if", "then", "else", "propertyNames",
    "additionalProperties", "unevaluatedProperties", "contentSchema",
}
MAP_SCHEMA_KEYS = {"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"}
LIST_SCHEMA_KEYS = {"allOf", "anyOf", "oneOf", "prefixItems"}


def audit_schema(schema: Any, *, tool_name: str, location: str, is_input: bool,
                 policy: Policy) -> tuple[list[dict[str, str]], dict[str, Any]]:
    findings: list[dict[str, str]] = []
    metrics = {"subschemas": 0, "max_depth": 0, "headers": [], "external_refs": 0, "open_objects": 0}
    if not isinstance(schema, dict):
        findings.append(finding("schema.object_required", "critical", location, "Schema must be a JSON object."))
        return findings, metrics
    dialect = schema.get("$schema", "https://json-schema.org/draft/2020-12/schema")
    if not isinstance(dialect, str) or dialect not in policy.allowed_schema_dialects:
        findings.append(finding("schema.dialect_denied", "high", f"{location}.$schema",
                                f"JSON Schema dialect {dialect!r} is not allowed by policy."))
    if is_input and schema.get("type") != "object":
        findings.append(finding("schema.input_root_object", "critical", f"{location}.type",
                                "MCP inputSchema root must declare type 'object'."))
    seen_headers: dict[str, str] = {}
    depth_reported = subschema_reported = False
    stack: list[tuple[Any, str, int, bool, bool, str | None]] = [
        (schema, location, 1, False, True, None)
    ]
    while stack:
        node, path, depth, is_property, statically_reachable, property_name = stack.pop()
        metrics["subschemas"] += 1
        metrics["max_depth"] = max(metrics["max_depth"], depth)
        if depth > policy.max_schema_depth and not depth_reported:
            findings.append(finding("schema.depth_limit", "high", path,
                                    f"Schema depth exceeds policy maximum {policy.max_schema_depth}."))
            depth_reported = True
        if metrics["subschemas"] > policy.max_subschemas and not subschema_reported:
            findings.append(finding("schema.subschema_limit", "high", path,
                                    f"Schema contains more than {policy.max_subschemas} subschemas."))
            subschema_reported = True
            break
        if depth > policy.max_schema_depth:
            continue
        if isinstance(node, bool):
            continue
        _audit_node(node, path, is_input, policy, findings, metrics)
        header = node.get("x-mcp-header")
        if header is not None:
            _audit_header(node, header, path, is_input, is_property, statically_reachable,
                          property_name, policy, seen_headers, findings, metrics)
        properties = node.get("properties")
        if properties is not None and not isinstance(properties, dict):
            findings.append(finding("schema.properties_type", "critical", f"{path}.properties",
                                    "Schema properties must be an object map."))
        elif isinstance(properties, dict):
            for name, child in reversed(list(properties.items())):
                child_path = f"{path}.properties.{name}"
                if isinstance(child, (dict, bool)):
                    stack.append((child, child_path, depth + 1, True, statically_reachable, name))
                else:
                    findings.append(finding("schema.subschema_type", "critical", child_path,
                                            "Property schema must be an object."))
        for key in MAP_SCHEMA_KEYS - {"properties"}:
            value = node.get(key)
            if value is None:
                continue
            if not isinstance(value, dict):
                findings.append(finding("schema.map_keyword_type", "high", f"{path}.{key}",
                                        f"Schema keyword {key!r} must be an object map."))
                continue
            for name, child in reversed(list(value.items())):
                if isinstance(child, (dict, bool)):
                    stack.append((child, f"{path}.{key}.{name}", depth + 1, False, False, None))
        for key in SINGLE_SCHEMA_KEYS:
            child = node.get(key)
            if isinstance(child, (dict, bool)):
                stack.append((child, f"{path}.{key}", depth + 1, False, False, None))
        for key in LIST_SCHEMA_KEYS:
            value = node.get(key)
            if value is None:
                continue
            if not isinstance(value, list):
                findings.append(finding("schema.list_keyword_type", "high", f"{path}.{key}",
                                        f"Schema keyword {key!r} must be a list."))
                continue
            for index, child in reversed(list(enumerate(value))):
                if isinstance(child, (dict, bool)):
                    stack.append((child, f"{path}.{key}[{index}]", depth + 1, False, False, None))
                else:
                    findings.append(finding("schema.subschema_type", "critical", f"{path}.{key}[{index}]",
                                            "Composed subschema must be an object."))
    return findings, metrics


def _audit_node(node: dict[str, Any], path: str, is_input: bool, policy: Policy,
                findings: list[dict[str, str]], metrics: dict[str, Any]) -> None:
    declared_type = node.get("type")
    if declared_type is not None:
        values = [declared_type] if isinstance(declared_type, str) else declared_type
        if (not isinstance(values, list) or not values or not all(isinstance(item, str) and item in JSON_TYPES for item in values)
                or len(values) != len(set(values))):
            findings.append(finding("schema.type_invalid", "critical", f"{path}.type",
                                    "Schema type must be a JSON type string or a unique non-empty list of JSON types."))
    required = node.get("required")
    if required is not None:
        if (not isinstance(required, list) or not all(isinstance(item, str) and item for item in required)
                or len(required) != len(set(required))):
            findings.append(finding("schema.required_invalid", "critical", f"{path}.required",
                                    "Required must be a unique list of non-empty property names."))
        elif isinstance(node.get("properties"), dict):
            for name in required:
                if name not in node["properties"]:
                    findings.append(finding("schema.required_unknown", "critical", f"{path}.required",
                                            f"Required property {name!r} is not declared in properties."))
    enum = node.get("enum")
    if enum is not None:
        if not isinstance(enum, list) or not enum:
            findings.append(finding("schema.enum_invalid", "high", f"{path}.enum", "Enum must be a non-empty list."))
        elif len({_canonical(item) for item in enum}) != len(enum):
            findings.append(finding("schema.enum_duplicate", "medium", f"{path}.enum", "Enum values contain duplicates."))
    reference = node.get("$ref")
    if reference is not None:
        if not isinstance(reference, str) or not reference:
            findings.append(finding("schema.ref_invalid", "critical", f"{path}.$ref", "$ref must be a non-empty string."))
        elif not reference.startswith("#"):
            metrics["external_refs"] += 1
            if not policy.allow_external_refs:
                findings.append(finding("schema.external_ref", "high", f"{path}.$ref",
                                        "External $ref is denied; bundle or use a same-document reference."))
    if is_input and _is_object_schema(node) and node.get("additionalProperties") is not False:
        metrics["open_objects"] += 1
        if policy.require_closed_input_schema:
            findings.append(finding("schema.open_object", "high", f"{path}.additionalProperties",
                                    "Input object permits undeclared properties; set additionalProperties to false."))


def _audit_header(node: dict[str, Any], header: Any, path: str, is_input: bool, is_property: bool,
                  statically_reachable: bool, property_name: str | None, policy: Policy,
                  seen: dict[str, str], findings: list[dict[str, str]], metrics: dict[str, Any]) -> None:
    location = f"{path}.x-mcp-header"
    if not isinstance(header, str) or not header or not HEADER_RE.fullmatch(header):
        findings.append(finding("header.name_invalid", "critical", location,
                                "x-mcp-header must be a non-empty HTTP field-name token."))
        return
    folded = header.casefold()
    if folded in seen:
        findings.append(finding("header.duplicate", "critical", location,
                                f"x-mcp-header duplicates the case-insensitive header declared at {seen[folded]}."))
    else:
        seen[folded] = location
    metrics["headers"].append({"name": header, "path": path})
    if not is_input:
        findings.append(finding("header.output_forbidden", "high", location, "x-mcp-header is only valid in inputSchema."))
    if not is_property or not statically_reachable:
        findings.append(finding("header.not_statically_reachable", "critical", location,
                                "x-mcp-header must be on a statically reachable input property."))
    declared_type = node.get("type")
    if declared_type not in {"string", "integer", "boolean"}:
        findings.append(finding("header.type_invalid", "critical", f"{path}.type",
                                "Header-mirrored property type must be string, integer, or boolean."))
    if declared_type == "integer":
        minimum, maximum = node.get("minimum"), node.get("maximum")
        if (not _number(minimum) or not _number(maximum)
                or minimum < -SAFE_INTEGER or maximum > SAFE_INTEGER):
            findings.append(finding("header.integer_range", "high", path,
                                    "Header-mirrored integer must constrain minimum/maximum to the IEEE-754 safe range."))
    allowed = {item.casefold() for item in policy.allowed_header_names}
    if folded not in allowed:
        findings.append(finding("header.not_allowed", "high", location,
                                f"Header name {header!r} is not allowed by policy."))
    description = node.get("description", "")
    if ((property_name and SENSITIVE_NAME_RE.search(property_name))
            or isinstance(description, str) and SENSITIVE_NAME_RE.search(description)):
        findings.append(finding("header.sensitive_parameter", "critical", location,
                                "Sensitive or personal parameter must not be mirrored into an HTTP header."))


def compare_schemas(before: Any, after: Any, *, location: str, is_input: bool) -> list[dict[str, str]]:
    if isinstance(before, bool) and isinstance(after, bool) and before != after:
        if after is True:
            return [_drift("schema.boolean_widened", "critical", location,
                           "Boolean schema changed from rejecting all values to accepting all values.")]
        return [_drift("schema.boolean_narrowed", "medium", location,
                       "Boolean schema changed from accepting all values to rejecting all values.")]
    if isinstance(before, (dict, bool)) and isinstance(after, (dict, bool)) and type(before) is not type(after):
        return [_drift("schema.form_changed", "high", location,
                       "Schema changed between object and boolean form and requires review.")]
    if not isinstance(before, dict) or not isinstance(after, dict):
        return []
    findings: list[dict[str, str]] = []
    _compare_node(before, after, location, is_input, findings)
    return findings


def _compare_node(before: dict[str, Any], after: dict[str, Any], path: str, is_input: bool,
                  findings: list[dict[str, str]]) -> None:
    before_types, after_types = _types(before), _types(after)
    if before_types and not after_types:
        findings.append(_drift("schema.type_constraint_removed", "high", f"{path}.type",
                               "Schema type constraint was removed."))
    elif after_types - before_types:
        findings.append(_drift("schema.type_widened", "high", f"{path}.type",
                               f"Schema accepts {len(after_types - before_types)} additional type(s)."))
    elif before_types - after_types:
        findings.append(_drift("schema.type_narrowed", "medium", f"{path}.type",
                               "Schema type set was narrowed, which may break callers."))
    before_required, after_required = _strings(before.get("required")), _strings(after.get("required"))
    removed_required = before_required - after_required
    if removed_required:
        findings.append(_drift("schema.required_removed", "high", f"{path}.required",
                               f"{len(removed_required)} previously required parameter(s) became optional."))
    added_required = after_required - before_required
    if added_required:
        findings.append(_drift("schema.required_added", "medium", f"{path}.required",
                               f"{len(added_required)} parameter(s) became required."))
    before_props = before.get("properties") if isinstance(before.get("properties"), dict) else {}
    after_props = after.get("properties") if isinstance(after.get("properties"), dict) else {}
    for name in sorted(set(after_props) - set(before_props)):
        severity = "high" if is_input else "low"
        findings.append(_drift("schema.property_added", severity, f"{path}.properties.{name}",
                               f"{'Input' if is_input else 'Output'} property {name!r} was added."))
    for name in sorted(set(before_props) - set(after_props)):
        severity = "medium" if is_input else "high"
        findings.append(_drift("schema.property_removed", severity, f"{path}.properties.{name}",
                               f"{'Input' if is_input else 'Output'} property {name!r} was removed."))
    for name in sorted(set(before_props) & set(after_props)):
        child_path = f"{path}.properties.{name}"
        if isinstance(before_props[name], dict) and isinstance(after_props[name], dict):
            _compare_node(before_props[name], after_props[name], child_path, is_input, findings)
        else:
            findings.extend(compare_schemas(before_props[name], after_props[name], location=child_path, is_input=is_input))
    before_open = before.get("additionalProperties") is not False
    after_open = after.get("additionalProperties") is not False
    if not before_open and after_open:
        findings.append(_drift("schema.additional_properties_opened", "critical", f"{path}.additionalProperties",
                               "Object changed from closed to accepting undeclared properties."))
    elif before_open and not after_open:
        findings.append(_drift("schema.additional_properties_closed", "low", f"{path}.additionalProperties",
                               "Object now rejects undeclared properties."))
    _compare_enum(before, after, path, findings)
    _compare_bounds(before, after, path, findings)
    if before.get("pattern") is not None and before.get("pattern") != after.get("pattern"):
        findings.append(_drift("schema.pattern_weakened", "high", f"{path}.pattern",
                               "A string pattern constraint was removed or changed."))
    if before.get("const") is not None and before.get("const") != after.get("const"):
        findings.append(_drift("schema.const_changed", "high", f"{path}.const", "A const constraint was removed or changed."))
    if before.get("format") is not None and before.get("format") != after.get("format"):
        findings.append(_drift("schema.format_changed", "high", f"{path}.format", "A format annotation/constraint was removed or changed."))
    if before.get("uniqueItems") is True and after.get("uniqueItems") is not True:
        findings.append(_drift("schema.uniqueness_removed", "high", f"{path}.uniqueItems",
                               "Array item uniqueness constraint was removed."))
    if before.get("multipleOf") is not None and before.get("multipleOf") != after.get("multipleOf"):
        findings.append(_drift("schema.multiple_changed", "high", f"{path}.multipleOf",
                               "Numeric multipleOf constraint was removed or changed."))
    if _canonical(before.get("default", _MISSING)) != _canonical(after.get("default", _MISSING)):
        findings.append(_drift("schema.default_changed", "medium", f"{path}.default", "Schema default value changed."))
    before_header, after_header = before.get("x-mcp-header"), after.get("x-mcp-header")
    if before_header is None and after_header is not None:
        findings.append(_drift("schema.header_added", "high", f"{path}.x-mcp-header",
                               "Parameter is newly mirrored into an HTTP header."))
    elif before_header != after_header:
        findings.append(_drift("schema.header_changed", "high", f"{path}.x-mcp-header",
                               "Header mirroring name was changed or removed."))
    for key in (
        "allOf", "anyOf", "oneOf", "not", "if", "then", "else", "dependentSchemas",
        "dependentRequired", "unevaluatedProperties", "items", "prefixItems", "contains",
        "propertyNames", "patternProperties",
    ):
        if _canonical(before.get(key, _MISSING)) != _canonical(after.get(key, _MISSING)):
            findings.append(_drift("schema.composition_changed", "high", f"{path}.{key}",
                                   f"Schema keyword {key!r} changed and requires review."))
    if before.get("$ref") != after.get("$ref") and ("$ref" in before or "$ref" in after):
        findings.append(_drift("schema.ref_changed", "high", f"{path}.$ref", "Schema reference changed."))


def _compare_enum(before: dict[str, Any], after: dict[str, Any], path: str,
                  findings: list[dict[str, str]]) -> None:
    old = {_canonical(item) for item in before.get("enum", [])} if isinstance(before.get("enum"), list) else None
    new = {_canonical(item) for item in after.get("enum", [])} if isinstance(after.get("enum"), list) else None
    if old is not None and new is None:
        findings.append(_drift("schema.enum_removed", "high", f"{path}.enum", "Enum constraint was removed."))
    elif old is not None and new is not None and new - old:
        findings.append(_drift("schema.enum_expanded", "high", f"{path}.enum",
                               f"Enum accepts {len(new - old)} additional value(s)."))
    elif old is not None and new is not None and old - new:
        findings.append(_drift("schema.enum_narrowed", "medium", f"{path}.enum", "Enum was narrowed."))


def _compare_bounds(before: dict[str, Any], after: dict[str, Any], path: str,
                    findings: list[dict[str, str]]) -> None:
    for key in ("minimum", "exclusiveMinimum", "minLength", "minItems", "minProperties", "minContains"):
        old, new = before.get(key), after.get(key)
        if _number(old) and (not _number(new) or new < old):
            findings.append(_drift("schema.lower_bound_relaxed", "high", f"{path}.{key}", f"Constraint {key!r} was relaxed."))
    for key in ("maximum", "exclusiveMaximum", "maxLength", "maxItems", "maxProperties", "maxContains"):
        old, new = before.get(key), after.get(key)
        if _number(old) and (not _number(new) or new > old):
            findings.append(_drift("schema.upper_bound_relaxed", "high", f"{path}.{key}", f"Constraint {key!r} was relaxed."))


def _types(node: dict[str, Any]) -> set[str]:
    value = node.get("type")
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {item for item in value if isinstance(item, str)}
    return set()


def _strings(value: Any) -> set[str]:
    return {item for item in value if isinstance(item, str)} if isinstance(value, list) else set()


def _is_object_schema(node: dict[str, Any]) -> bool:
    declared = node.get("type")
    return declared == "object" or isinstance(declared, list) and "object" in declared


def _number(value: Any) -> bool:
    return type(value) in (int, float)


_MISSING = object()


def _canonical(value: Any) -> str:
    if value is _MISSING:
        return "<missing>"
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _drift(rule_id: str, severity: str, location: str, message: str) -> dict[str, str]:
    return finding(rule_id, severity, location, message, category="drift")
