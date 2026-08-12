"""Self-contained HTML report."""

from __future__ import annotations

from html import escape
from pathlib import Path


def write_html(result, path):
    summary = result["summary"]
    tool_rows = "".join(
        f"<tr><td>{escape(str(tool['name']))}</td><td>{'yes' if tool['has_output_schema'] else 'no'}</td>"
        f"<td>{escape(', '.join(tool['header_names']) or '-')}</td>"
        f"<td>{_risk_badges(tool['annotations'])}</td></tr>" for tool in result["tools"]
    ) or '<tr><td colspan="4">No tools declared.</td></tr>'
    findings = "".join(
        "<tr>"
        f"<td><span class='severity {escape(item['severity'])}'>{escape(item['severity'])}</span></td>"
        f"<td>{escape(item['rule_id'])}</td><td><code>{escape(item['location'])}</code></td>"
        f"<td>{escape(item['message'])}</td></tr>" for item in result["findings"]
    ) or '<tr><td colspan="4">No findings. This policy gate passed cleanly.</td></tr>'
    server = result["server"] if isinstance(result["server"], dict) else {}
    accent = "#ff617d" if result["verdict"] == "FAIL" else "#35e3a1"
    html = f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>MCP Tool Sentinel</title><style>
:root{{--accent:{accent};--ink:#eefaff;--muted:#9fc3cf;--panel:#11272f;--line:#2b5564}}*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(circle at 12% 0,#173448 0,#07151c 42%);color:var(--ink);font:15px/1.5 system-ui}}main{{max-width:1240px;margin:auto;padding:46px 24px}}h1{{font-size:40px;margin:5px 0}}.eyebrow{{color:#79e1ff;text-transform:uppercase;letter-spacing:.15em;font-weight:800}}.lede{{color:var(--muted);max-width:800px}}.cards{{display:grid;grid-template-columns:repeat(6,1fr);gap:11px;margin:24px 0}}.card,.panel{{background:var(--panel);border:1px solid var(--line);border-radius:15px}}.card{{padding:15px}}.card span{{display:block;color:var(--muted)}}.card strong{{display:block;color:var(--accent);font-size:24px}}.panel{{padding:20px;margin-top:16px;overflow:auto}}table{{width:100%;border-collapse:collapse}}th,td{{padding:10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}th{{color:#8ce5ff}}code{{color:#d7f7ff}}.badge{{display:inline-block;border:1px solid #377087;border-radius:99px;padding:2px 7px;margin:2px}}.severity{{border-radius:6px;padding:2px 7px;font-weight:700}}.critical{{background:#831843}}.high{{background:#7c2d12}}.medium{{background:#713f12}}.low{{background:#164e63}}.fingerprint{{word-break:break-all;color:var(--muted)}}@media(max-width:900px){{.cards{{grid-template-columns:repeat(2,1fr)}}}}</style></head><body><main><div class="eyebrow">Schema supply-chain gate</div><h1>MCP Tool Sentinel</h1><p class="lede">MCP tool descriptions, JSON Schema widening, x-mcp-header exposure, untrusted annotations, and privilege drift.</p><section class="cards"><div class="card"><span>Verdict</span><strong>{result['verdict']}</strong></div><div class="card"><span>Risk</span><strong>{summary['risk_score']}/100</strong></div><div class="card"><span>Blocking</span><strong>{summary['blocking_findings']}</strong></div><div class="card"><span>Tools</span><strong>{summary['tools']}</strong></div><div class="card"><span>Headers</span><strong>{summary['headers']}</strong></div><div class="card"><span>Open objects</span><strong>{summary['open_input_objects']}</strong></div></section><section class="panel"><h2>Snapshot</h2><p><b>Server:</b> {escape(str(server.get('name')))} {escape(str(server.get('version')))} · <b>Protocol:</b> {escape(str(result['protocol_version']))} · <b>Baseline compared:</b> {'yes' if summary['baseline_compared'] else 'no'}</p><p class="fingerprint">{escape(result['fingerprint'])}</p></section><section class="panel"><h2>Tool inventory</h2><table><thead><tr><th>Tool</th><th>Output schema</th><th>Header mirrors</th><th>Effective hints</th></tr></thead><tbody>{tool_rows}</tbody></table></section><section class="panel"><h2>Findings</h2><table><thead><tr><th>Severity</th><th>Rule</th><th>JSON path</th><th>Message</th></tr></thead><tbody>{findings}</tbody></table></section><section class="panel"><p class="lede">Annotations are displayed as effective pessimistic defaults, but remain untrusted hints. Sentinel does not execute tools or prove server behavior.</p></section></main></body></html>"""
    destination = Path(path)
    destination.write_text(html, encoding="utf-8")
    return destination


def _risk_badges(annotations):
    labels = {
        "readOnlyHint": "read-only", "destructiveHint": "destructive",
        "idempotentHint": "idempotent", "openWorldHint": "open-world",
    }
    return "".join(f"<span class='badge'>{labels[key]}={str(value).lower()}</span>" for key, value in annotations.items())
