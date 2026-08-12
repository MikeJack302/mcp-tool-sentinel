"""Security-relevant semantic drift across MCP tool snapshots."""

from __future__ import annotations

from typing import Any

from .model import Policy
from .schema import compare_schemas
from .utils import finding, fingerprint


ANNOTATION_DEFAULTS = {
    "readOnlyHint": False,
    "destructiveHint": True,
    "idempotentHint": False,
    "openWorldHint": True,
}


def audit_drift(baseline: dict[str, Any], current: dict[str, Any], policy: Policy) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    old_tools = _tool_map(baseline)
    new_tools = _tool_map(current)
    old_version = _server_version(baseline)
    new_version = _server_version(current)
    if fingerprint(baseline) != fingerprint(current) and old_version == new_version:
        findings.append(_drift("drift.unversioned_snapshot", "high", "$.serverInfo.version",
                               "Tool snapshot changed without changing the MCP server version."))
    elif old_version != new_version:
        findings.append(_drift("drift.server_version_changed", "low", "$.serverInfo.version",
                               f"Server version changed from {old_version!r} to {new_version!r}."))
    if baseline.get("protocolVersion") != current.get("protocolVersion"):
        findings.append(_drift("drift.protocol_version_changed", "high", "$.protocolVersion",
                               "MCP protocol version changed and requires compatibility review."))
    old_order = _tool_order(baseline)
    new_order = _tool_order(current)
    if set(old_order) == set(new_order) and old_order != new_order:
        findings.append(_drift("drift.tool_order_changed", "low", "$.tools",
                               "Tool order changed; deterministic ordering improves caching and stable model context."))
    for name in sorted(set(new_tools) - set(old_tools)):
        severity = "low" if policy.allow_new_tools else "high"
        findings.append(_drift("drift.tool_added", severity, "$.tools", f"Tool {name!r} was added."))
    for name in sorted(set(old_tools) - set(new_tools)):
        findings.append(_drift("drift.tool_removed", "medium", "$.tools", f"Tool {name!r} was removed."))
    for name in sorted(set(old_tools) & set(new_tools)):
        before, after = old_tools[name], new_tools[name]
        location = f"$.tools[{after[0]}]"
        old_tool, new_tool = before[1], after[1]
        if old_tool.get("description") != new_tool.get("description"):
            findings.append(_drift("drift.description_changed", "high", f"{location}.description",
                                   f"Model-visible description for tool {name!r} changed."))
        if old_tool.get("title") != new_tool.get("title"):
            findings.append(_drift("drift.title_changed", "low", f"{location}.title", f"Title for tool {name!r} changed."))
        findings.extend(_annotation_drift(old_tool, new_tool, location, name))
        findings.extend(compare_schemas(old_tool.get("inputSchema"), new_tool.get("inputSchema"),
                                        location=f"{location}.inputSchema", is_input=True))
        old_output, new_output = old_tool.get("outputSchema"), new_tool.get("outputSchema")
        if isinstance(old_output, dict) and not isinstance(new_output, dict):
            findings.append(_drift("drift.output_schema_removed", "high", f"{location}.outputSchema",
                                   f"Output schema for tool {name!r} was removed."))
        elif isinstance(old_output, dict) and isinstance(new_output, dict):
            findings.extend(compare_schemas(old_output, new_output, location=f"{location}.outputSchema", is_input=False))
        elif not isinstance(old_output, dict) and isinstance(new_output, dict):
            findings.append(_drift("drift.output_schema_added", "low", f"{location}.outputSchema",
                                   f"Output schema for tool {name!r} was added."))
    return findings


def _annotation_drift(before: dict[str, Any], after: dict[str, Any], location: str,
                      tool_name: str) -> list[dict[str, str]]:
    old = effective_annotations(before.get("annotations"))
    new = effective_annotations(after.get("annotations"))
    result = []
    transitions = (
        ("readOnlyHint", True, False, "high", "Tool may now modify state."),
        ("destructiveHint", False, True, "high", "Tool may now perform destructive updates."),
        ("idempotentHint", True, False, "medium", "Tool is no longer declared safe to retry."),
        ("openWorldHint", False, True, "high", "Tool may now interact with external entities."),
    )
    for key, old_value, new_value, severity, message in transitions:
        if old[key] is old_value and new[key] is new_value:
            result.append(_drift("drift.annotation_risk_increased", severity, f"{location}.annotations.{key}",
                                 f"{tool_name!r}: {message}"))
    safer_claims = (
        ("readOnlyHint", False, True, "Tool newly claims to be read-only."),
        ("destructiveHint", True, False, "Tool newly claims not to be destructive."),
        ("idempotentHint", False, True, "Tool newly claims to be safe to retry."),
        ("openWorldHint", True, False, "Tool newly claims a closed interaction world."),
    )
    for key, old_value, new_value, message in safer_claims:
        if old[key] is old_value and new[key] is new_value:
            result.append(_drift("drift.annotation_claims_safer", "high", f"{location}.annotations.{key}",
                                 f"{tool_name!r}: {message} This untrusted hint may change client confirmation behavior."))
    return result


def effective_annotations(value: Any) -> dict[str, bool]:
    source = value if isinstance(value, dict) else {}
    return {key: source.get(key) if type(source.get(key)) is bool else default
            for key, default in ANNOTATION_DEFAULTS.items()}


def _tool_map(snapshot: dict[str, Any]) -> dict[str, tuple[int, dict[str, Any]]]:
    result = {}
    tools = snapshot.get("tools")
    if not isinstance(tools, list):
        return result
    for index, tool in enumerate(tools):
        if isinstance(tool, dict) and isinstance(tool.get("name"), str):
            if tool["name"] in result:
                raise ValueError(f"baseline/current contains duplicate tool name {tool['name']!r}")
            result[tool["name"]] = (index, tool)
    return result


def _tool_order(snapshot: dict[str, Any]) -> list[str]:
    tools = snapshot.get("tools")
    return [item["name"] for item in tools if isinstance(item, dict) and isinstance(item.get("name"), str)] \
        if isinstance(tools, list) else []


def _server_version(snapshot: dict[str, Any]) -> Any:
    server = snapshot.get("serverInfo")
    return server.get("version") if isinstance(server, dict) else None


def _drift(rule_id: str, severity: str, location: str, message: str) -> dict[str, str]:
    return finding(rule_id, severity, location, message, category="drift")
