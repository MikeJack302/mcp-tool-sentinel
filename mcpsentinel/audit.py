"""Deterministic MCP tool snapshot policy audit."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from .drift import audit_drift, effective_annotations
from .model import Policy
from .schema import audit_schema
from .utils import (
    DANGEROUS_TOOL_RE, DESTRUCTIVE_TOOL_RE, INJECTION_PATTERNS, OPEN_WORLD_TOOL_RE,
    SECRET_PATTERNS, finding, fingerprint, walk_strings,
)


TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
ANNOTATION_KEYS = {"title", "readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"}


def audit_snapshot(snapshot: Any, policy: Policy, *, baseline: Any | None = None) -> dict[str, Any]:
    if not isinstance(snapshot, dict):
        raise ValueError("MCP snapshot must be a JSON object")
    if baseline is not None and not isinstance(baseline, dict):
        raise ValueError("baseline MCP snapshot must be a JSON object")
    policy.validate()
    findings: list[dict[str, str]] = []
    _audit_snapshot_metadata(snapshot, policy, findings)
    tools = snapshot.get("tools")
    if not isinstance(tools, list):
        tools = []
    if len(tools) > policy.max_tools:
        findings.append(finding("snapshot.tool_limit", "high", "$.tools",
                                f"Snapshot contains {len(tools)} tools; policy maximum is {policy.max_tools}."))
    seen = set()
    inventories = []
    schema_totals = {"subschemas": 0, "headers": 0, "external_refs": 0, "open_objects": 0}
    for index, tool in enumerate(tools):
        location = f"$.tools[{index}]"
        if not isinstance(tool, dict):
            findings.append(finding("tool.object_required", "critical", location, "Tool must be an object."))
            continue
        name = tool.get("name")
        if not isinstance(name, str) or not TOOL_NAME_RE.fullmatch(name):
            findings.append(finding("tool.name_invalid", "critical", f"{location}.name",
                                    "Tool name must be 1-128 characters using letters, digits, underscore, hyphen, or dot."))
            name = name if isinstance(name, str) else f"<invalid-{index}>"
        if name in seen:
            findings.append(finding("tool.name_duplicate", "critical", f"{location}.name", f"Duplicate tool name {name!r}."))
        seen.add(name)
        _audit_description(tool, location, name, policy, findings)
        annotation_inventory = _audit_annotations(tool, location, name, policy, findings)
        input_findings, input_metrics = audit_schema(tool.get("inputSchema"), tool_name=name,
                                                     location=f"{location}.inputSchema", is_input=True, policy=policy)
        findings.extend(input_findings)
        _merge_schema_metrics(schema_totals, input_metrics)
        output = tool.get("outputSchema")
        if output is None and policy.require_output_schema:
            findings.append(finding("tool.output_schema_required", "high", f"{location}.outputSchema",
                                    f"Tool {name!r} requires an output schema by policy."))
        elif output is not None:
            output_findings, output_metrics = audit_schema(output, tool_name=name,
                                                           location=f"{location}.outputSchema", is_input=False, policy=policy)
            findings.extend(output_findings)
            _merge_schema_metrics(schema_totals, output_metrics)
        _audit_icons(tool.get("icons"), location, findings)
        _audit_untrusted_strings(tool, location, policy, findings)
        inventories.append({
            "name": name,
            "has_output_schema": isinstance(output, dict),
            "annotations": annotation_inventory,
            "header_names": [item["name"] for item in input_metrics["headers"]],
            "input_open_objects": input_metrics["open_objects"],
        })
    if schema_totals["headers"] and snapshot.get("protocolVersion") != "2026-07-28":
        findings.append(finding("header.protocol_version", "high", "$.protocolVersion",
                                "x-mcp-header requires MCP protocol version 2026-07-28."))
    if baseline is not None:
        _validate_baseline_shape(baseline)
        findings.extend(audit_drift(baseline, snapshot, policy))
    weights = {"critical": 25, "high": 12, "medium": 5, "low": 1}
    counts = {severity: sum(item["severity"] == severity for item in findings)
              for severity in ("critical", "high", "medium", "low")}
    blocking = counts["critical"] + counts["high"]
    return {
        "verdict": "FAIL" if blocking else "PASS",
        "fingerprint": fingerprint(snapshot),
        "summary": {
            "tools": len(tools), "findings": len(findings), "blocking_findings": blocking,
            "risk_score": min(100, sum(weights[item["severity"]] for item in findings)),
            "counts": counts, "baseline_compared": baseline is not None,
            "subschemas": schema_totals["subschemas"], "headers": schema_totals["headers"],
            "external_refs": schema_totals["external_refs"], "open_input_objects": schema_totals["open_objects"],
        },
        "server": snapshot.get("serverInfo"),
        "protocol_version": snapshot.get("protocolVersion"),
        "tools": inventories,
        "findings": findings,
    }


def _audit_snapshot_metadata(snapshot: dict[str, Any], policy: Policy,
                             findings: list[dict[str, str]]) -> None:
    version = snapshot.get("protocolVersion")
    if not isinstance(version, str) or not version:
        findings.append(finding("snapshot.protocol_required", "critical", "$.protocolVersion",
                                "Snapshot protocolVersion is required."))
    elif version not in policy.allowed_protocol_versions:
        findings.append(finding("snapshot.protocol_denied", "high", "$.protocolVersion",
                                f"Protocol version {version!r} is not allowed by policy."))
    server = snapshot.get("serverInfo")
    if not isinstance(server, dict):
        findings.append(finding("snapshot.server_info_required", "critical", "$.serverInfo",
                                "Snapshot serverInfo object is required."))
    else:
        for key in ("name", "version"):
            if not isinstance(server.get(key), str) or not server.get(key, "").strip():
                findings.append(finding("snapshot.server_info_invalid", "critical", f"$.serverInfo.{key}",
                                        f"serverInfo.{key} must be a non-empty string."))
    if not isinstance(snapshot.get("tools"), list):
        findings.append(finding("snapshot.tools_required", "critical", "$.tools", "Snapshot tools must be a list."))


def _audit_description(tool: dict[str, Any], location: str, name: str, policy: Policy,
                       findings: list[dict[str, str]]) -> None:
    description = tool.get("description")
    if description is None and policy.require_descriptions:
        findings.append(finding("tool.description_required", "high", f"{location}.description",
                                f"Tool {name!r} requires a model-visible description."))
    elif description is not None and (not isinstance(description, str) or not description.strip()):
        findings.append(finding("tool.description_invalid", "high", f"{location}.description",
                                "Tool description must be a non-empty string."))
    elif isinstance(description, str) and len(description) > policy.max_description_chars:
        findings.append(finding("tool.description_too_long", "medium", f"{location}.description",
                                f"Tool description exceeds {policy.max_description_chars} characters."))


def _audit_annotations(tool: dict[str, Any], location: str, name: str, policy: Policy,
                       findings: list[dict[str, str]]) -> dict[str, bool]:
    value = tool.get("annotations")
    if value is None:
        if policy.require_annotations:
            findings.append(finding("annotation.required", "high", f"{location}.annotations",
                                    f"Tool {name!r} must explicitly declare risk annotations."))
        value = {}
    elif not isinstance(value, dict):
        findings.append(finding("annotation.object_required", "critical", f"{location}.annotations",
                                "Tool annotations must be an object."))
        value = {}
    for key in set(value) - ANNOTATION_KEYS:
        findings.append(finding("annotation.unknown", "low", f"{location}.annotations.{key}",
                                f"Unknown annotation {key!r} is retained as untrusted metadata."))
    for key in ANNOTATION_KEYS - {"title"}:
        if key in value and type(value[key]) is not bool:
            findings.append(finding("annotation.boolean_required", "critical", f"{location}.annotations.{key}",
                                    f"Annotation {key!r} must be boolean."))
    if "title" in value and not isinstance(value["title"], str):
        findings.append(finding("annotation.title_invalid", "medium", f"{location}.annotations.title",
                                "Annotation title must be a string."))
    effective = effective_annotations(value)
    if effective["readOnlyHint"] and value.get("destructiveHint") is True:
        findings.append(finding("annotation.ignored_destructive_hint", "medium", f"{location}.annotations",
                                "destructiveHint is explicitly true but ignored while readOnlyHint is true."))
    if effective["readOnlyHint"] and not effective["idempotentHint"]:
        findings.append(finding("annotation.readonly_not_idempotent", "low", f"{location}.annotations",
                                "Read-only tool is not declared idempotent; verify the hint combination."))
    if DANGEROUS_TOOL_RE.search(name) and effective["readOnlyHint"]:
        findings.append(finding("annotation.suspicious_readonly", "high", f"{location}.annotations.readOnlyHint",
                                f"Action-oriented tool {name!r} claims to be read-only."))
    if DESTRUCTIVE_TOOL_RE.search(name) and not effective["destructiveHint"]:
        findings.append(finding("annotation.suspicious_nondestructive", "high", f"{location}.annotations.destructiveHint",
                                f"Destructive-looking tool {name!r} claims not to be destructive."))
    if OPEN_WORLD_TOOL_RE.search(name) and not effective["openWorldHint"]:
        findings.append(finding("annotation.suspicious_closed_world", "high", f"{location}.annotations.openWorldHint",
                                f"Externally oriented tool {name!r} claims a closed world."))
    return effective


def _audit_icons(value: Any, location: str, findings: list[dict[str, str]]) -> None:
    if value is None:
        return
    if not isinstance(value, list):
        findings.append(finding("icon.list_required", "medium", f"{location}.icons", "Icons must be a list."))
        return
    for index, icon in enumerate(value):
        path = f"{location}.icons[{index}]"
        if not isinstance(icon, dict) or not isinstance(icon.get("src"), str):
            findings.append(finding("icon.invalid", "medium", path, "Icon must be an object with a string src."))
            continue
        try:
            parsed = urlparse(icon["src"])
            if parsed.scheme not in {"https", "data"}:
                findings.append(finding("icon.scheme", "medium", f"{path}.src", "Icon should use HTTPS or a data URL."))
        except ValueError:
            findings.append(finding("icon.invalid", "medium", f"{path}.src", "Icon URL is malformed."))


def _audit_untrusted_strings(tool: dict[str, Any], location: str, policy: Policy,
                             findings: list[dict[str, str]]) -> None:
    for relative, value in walk_strings(tool):
        path = location + relative[1:]
        if any(pattern.search(value) for pattern in SECRET_PATTERNS):
            findings.append(finding("content.embedded_secret", "critical", path,
                                    "Tool metadata resembles an embedded credential or private key; value redacted."))
        if (policy.block_prompt_injection and relative.endswith(".description")
                and any(pattern.search(value) for pattern in INJECTION_PATTERNS)):
            findings.append(finding("content.prompt_injection", "high", path,
                                    "Model-visible description matches a prompt-injection pattern."))


def _merge_schema_metrics(total: dict[str, int], current: dict[str, Any]) -> None:
    total["subschemas"] += current["subschemas"]
    total["headers"] += len(current["headers"])
    total["external_refs"] += current["external_refs"]
    total["open_objects"] += current["open_objects"]


def _validate_baseline_shape(snapshot: dict[str, Any]) -> None:
    if not isinstance(snapshot.get("tools"), list):
        raise ValueError("baseline snapshot tools must be a list")
    names = [tool.get("name") for tool in snapshot["tools"] if isinstance(tool, dict)]
    valid = [name for name in names if isinstance(name, str)]
    if len(valid) != len(snapshot["tools"]) or len(valid) != len(set(valid)):
        raise ValueError("baseline snapshot tools require unique string names")
