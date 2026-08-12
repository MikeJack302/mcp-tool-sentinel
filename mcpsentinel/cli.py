"""Command-line interface."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .audit import audit_snapshot
from .model import load_json, load_policy
from .report import write_html
from .sarif import write_sarif


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-tool-sentinel", description="Audit MCP tool schemas and privilege drift.")
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("-o", "--output", type=Path, default=Path("mcp-tool-report.html"))
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--sarif-output", type=Path)
    parser.add_argument("--no-fail", action="store_true")
    parser.add_argument("--version", action="version", version="mcp-tool-sentinel 0.1.0")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    try:
        baseline = load_json(args.baseline) if args.baseline else None
        result = audit_snapshot(load_json(args.snapshot), load_policy(args.policy), baseline=baseline)
        report = write_html(result, args.output).resolve()
        if args.json_output:
            args.json_output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        if args.sarif_output:
            write_sarif(result, args.sarif_output, args.snapshot.as_posix())
        summary = result["summary"]
        print(f"{result['verdict']} | risk={summary['risk_score']}/100 | blocking={summary['blocking_findings']} | report={report}")
        return 0 if args.no_fail or result["verdict"] == "PASS" else 2
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
