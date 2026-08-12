"""SARIF 2.1.0 output."""

from __future__ import annotations

import json
from pathlib import Path


def build_sarif(result, artifact_uri: str) -> dict:
    rules = {}
    for item in result["findings"]:
        rules.setdefault(item["rule_id"], {
            "id": item["rule_id"],
            "shortDescription": {"text": item["message"]},
            "properties": {"category": item["category"], "defaultSeverity": item["severity"]},
        })
    levels = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "MCP Tool Sentinel", "version": "0.1.0", "rules": list(rules.values())}},
            "results": [{
                "ruleId": item["rule_id"], "level": levels[item["severity"]],
                "message": {"text": f"{item['location']}: {item['message']}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": artifact_uri}}}],
                "properties": {"jsonPath": item["location"], "severity": item["severity"]},
            } for item in result["findings"]],
        }],
    }


def write_sarif(result, path, artifact_uri: str):
    destination = Path(path)
    destination.write_text(json.dumps(build_sarif(result, artifact_uri), ensure_ascii=False, indent=2), encoding="utf-8")
    return destination
