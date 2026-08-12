# Security policy

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting. Do not post production tool snapshots, credentials, private schemas, internal server names, or unpatched findings in a public issue.

## Data handling

MCP Tool Sentinel runs locally and makes no network requests. Reports include server identity, tool names, header names, annotations, JSON paths, and finding messages, but not raw Schema documents or descriptions. Detected credential-like values are redacted from finding text.

The examples contain documentation-only placeholders, not working credentials.

Sentinel does not execute tools, authenticate an MCP server, fully validate JSON Schema, verify package provenance, or enforce runtime authorization. A PASS must not be used to skip confirmation, sandboxing, input/output validation, rate limits, or audit logging.
