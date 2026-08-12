# Contributing

Thanks for improving MCP Tool Sentinel.

1. Open an issue describing the MCP field, Schema construct, privilege change, false positive, or false negative.
2. Link the released MCP specification, JSON Schema standard, or another primary source.
3. Add a focused regression test. Malformed input must demonstrate bounded behavior and must not crash the audit unexpectedly.
4. Run `python -m unittest discover -s tests -v` and `python -m compileall -q mcpsentinel`.
5. Explain whether the change affects conformance, security, compatibility, or policy defaults.

Keep live server calls, external `$ref` retrieval, cryptographic provenance, and full meta-schema validation explicit and opt-in. The offline core should remain deterministic and dependency-free.
