# MCP Tool Sentinel

[![CI](https://github.com/MikeJack302/mcp-tool-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/MikeJack302/mcp-tool-sentinel/actions/workflows/ci.yml)
[![MCP 2026-07-28](https://img.shields.io/badge/MCP-2026--07--28-58d68d)](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776ab)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-22c55e)](LICENSE)

An offline, dependency-free supply-chain and privilege-drift gate for Model Context Protocol tool definitions.

MCP tools are model-visible interfaces. A small metadata update can change tool selection, suppress a confirmation, expose a sensitive argument through an HTTP header, or turn a bounded JSON Schema into “accept anything.” MCP Tool Sentinel reviews a current snapshot against policy and, optionally, against a previously approved baseline.

## What it catches

- Invalid/duplicate tool names, missing descriptions, malformed annotations, unsafe icons, and oversized catalogs
- Prompt-injection phrases and credential-like text inside model-visible descriptions
- Input roots that are not objects, undeclared-property acceptance, external `$ref`, malformed types/required/enums, and bounded depth/size violations
- Invalid, duplicated, non-static, unapproved, unsafe-integer, or sensitive `x-mcp-header` mappings
- Suspicious risk hints such as `execute_payment` claiming read-only or `web_search` claiming a closed world
- New/removed/reordered tools and server/protocol version drift
- Model-visible description changes and tool annotations that claim either more risk or suspiciously less risk
- Required parameters becoming optional; properties, types, enums, bounds, patterns, defaults, headers, and composition changing
- Closed objects becoming open and output schemas disappearing

Results are deterministic JSON, a self-contained HTML report, and SARIF 2.1.0 for code scanning.

## Why this exists

The [MCP `2026-07-28` Tools specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) makes tools model-controlled and says sensitive operations should preserve human denial. It also promotes tool schemas to full JSON Schema 2020-12 and introduces `x-mcp-header`, while explicitly warning not to mirror passwords, API keys, tokens, or PII into headers. The [release notes](https://blog.modelcontextprotocol.io/posts/2026-07-28/) warn implementations not to automatically dereference external `$ref` URIs and to bound schema depth and validation time.

The official [tool-annotation risk guidance](https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/) emphasizes that annotations are untrusted hints. Their defaults are deliberately pessimistic: non-read-only, potentially destructive, non-idempotent, and open-world. Sentinel preserves those defaults and treats changes as review signals, not proof of behavior.

## Quick start

Windows PowerShell:

```powershell
git clone https://github.com/MikeJack302/mcp-tool-sentinel.git
cd mcp-tool-sentinel
py -m pip install .

mcp-tool-sentinel examples/risky-snapshot.json `
  --baseline examples/baseline-snapshot.json `
  --policy examples/policy.json `
  --json-output audit.json `
  --sarif-output audit.sarif `
  --output audit.html `
  --no-fail
```

Linux and WSL2:

```bash
python3 -m pip install .
mcp-tool-sentinel examples/risky-snapshot.json \
  --baseline examples/baseline-snapshot.json \
  --policy examples/policy.json \
  --json-output audit.json \
  --sarif-output audit.sarif \
  --output audit.html \
  --no-fail
```

The included baseline is clean. The deliberately risky payment-server update fails with open inputs, a sensitive header, prompt-like text, a new shell tool, annotation downgrades, and multiple Schema widenings. Remove `--no-fail` in CI; a policy failure then exits with code `2`.

## Snapshot format

Sentinel does not connect to a server. Wrap a trusted capture of `tools/list` with the negotiated protocol and server identity:

```json
{
  "protocolVersion": "2026-07-28",
  "serverInfo": {"name": "treasury-mcp", "version": "2.4.0"},
  "tools": [
    {
      "name": "lookup_invoice",
      "description": "Read one approved invoice.",
      "inputSchema": {
        "type": "object",
        "properties": {"invoice_id": {"type": "string"}},
        "required": ["invoice_id"],
        "additionalProperties": false
      },
      "annotations": {
        "readOnlyHint": true,
        "destructiveHint": false,
        "idempotentHint": true,
        "openWorldHint": false
      }
    }
  ]
}
```

Store the approved snapshot in version control. MCP `2026-07-28` allows `tools/list` to vary with per-request authorization, so capture and compare each relevant authorization profile separately.

## Policy

```json
{
  "allowed_protocol_versions": ["2026-07-28"],
  "allowed_schema_dialects": ["https://json-schema.org/draft/2020-12/schema"],
  "allowed_header_names": ["Region"],
  "allow_external_refs": false,
  "allow_new_tools": false,
  "require_descriptions": true,
  "require_annotations": true,
  "require_output_schema": false,
  "require_closed_input_schema": true,
  "block_prompt_injection": true,
  "max_tools": 50,
  "max_description_chars": 2000,
  "max_schema_depth": 32,
  "max_subschemas": 500
}
```

`allowed_header_names` is case-insensitive and fail-closed: the empty list permits no `x-mcp-header` values. Headers require protocol `2026-07-28`. Header-mirrored integers must define safe `minimum` and `maximum`; this is a deliberate hardening rule so the schema cannot accept values outside the MCP/IEEE-754 safe range.

`allow_new_tools` downgrades only the new-tool drift finding from high to low. Every new tool is still fully inspected. `require_closed_input_schema` applies to every input object, including nested object properties.

## Semantic drift

Sentinel highlights changes that ordinary JSON diffs obscure:

| Change | Default severity |
| --- | --- |
| Closed object becomes open; boolean `false` schema becomes `true` | Critical |
| Sensitive parameter mirrored into a header | Critical |
| Required parameter removed; type/enum/bound/pattern widened | High |
| Description, `$ref`, composition, header, format, or default changed | High or medium |
| Output schema removed | High |
| Annotation claims more privilege or suddenly claims safer behavior | High |
| New tool | High, or low when explicitly allowed |
| New required parameter / narrowed type or enum | Medium compatibility warning |
| Tool order or server version changed | Low |

Any critical or high finding fails. Medium and low findings remain visible without failing the gate. The risk score is explanatory (`critical=25`, `high=12`, `medium=5`, `low=1`) and capped at 100; it does not determine the verdict.

## CI example

```yaml
- name: Gate MCP tools
  run: >-
    mcp-tool-sentinel deploy/tools-snapshot.json
    --baseline approved/tools-snapshot.json
    --policy security/mcp-tool-policy.json
    --json-output mcp-audit.json
    --sarif-output mcp-audit.sarif
    --output mcp-audit.html
```

| Result | Exit code |
| --- | ---: |
| No critical/high findings | `0` |
| Critical/high finding present | `2` |
| Completed with `--no-fail` | `0` |
| Invalid file, snapshot, or policy | argparse error |

## Trust boundary

This is a static preflight review tool, not an MCP client, JSON Schema validator, or sandbox.

- It never launches or calls a server, validates tool results, authenticates a publisher, checks OAuth scopes, or proves that annotations match runtime behavior.
- It inspects the JSON Schema security subset used by its rules; it does not implement the complete JSON Schema 2020-12 meta-schema or decide logical equivalence. Complex composition changes are conservatively flagged for review.
- It never dereferences `$ref`. Same-document references are permitted by default; external references are reported unless policy explicitly allows them.
- Regex checks for dangerous names, prompt injection, secrets, and sensitive fields can have false positives and false negatives.
- `additionalProperties: false` narrows accepted JSON but does not establish business authorization. Servers must still validate all inputs and enforce access control.
- Descriptions and annotations remain untrusted after a PASS. Clients should show tool exposure and inputs, preserve human confirmation for sensitive operations, validate outputs, impose timeouts, and keep audit logs as the MCP specification recommends.
- Snapshot comparison depends on a trusted, authorization-matched baseline. A poisoned baseline can normalize malicious behavior.
- Input files are limited to 10 MB; Schema traversal is bounded by policy to resist pathological catalogs.

Use signature/provenance controls, server conformance testing, runtime policy enforcement, sandboxing, and network egress restrictions alongside Sentinel.

## Development

```bash
python -m unittest discover -s tests -v
python -m compileall -q mcpsentinel
```

The runtime has no third-party dependencies and supports Python 3.11+ on Windows, Linux, and WSL2. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
