from pathlib import Path
import tempfile
import unittest

from mcpsentinel.report import write_html
from mcpsentinel.sarif import build_sarif


class OutputTests(unittest.TestCase):
    def result(self):
        return {
            "verdict": "FAIL", "fingerprint": "sha256:abc", "protocol_version": "2026-07-28",
            "server": {"name": "<script>x</script>", "version": "1"},
            "summary": {"risk_score": 25, "blocking_findings": 1, "tools": 1, "headers": 1,
                        "open_input_objects": 1, "baseline_compared": True},
            "tools": [{"name": "<tool>", "has_output_schema": False, "header_names": ["<header>"],
                       "annotations": {"readOnlyHint": False, "destructiveHint": True,
                                       "idempotentHint": False, "openWorldHint": True}}],
            "findings": [{"rule_id": "x.rule", "severity": "critical", "location": "$.<x>",
                          "message": "<img src=x>", "category": "audit"}],
        }

    def test_html_escapes_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.html"
            write_html(self.result(), path)
            html = path.read_text(encoding="utf-8")
        self.assertNotIn("<script>x</script>", html)
        self.assertIn("&lt;tool&gt;", html)
        self.assertIn("&lt;img src=x&gt;", html)

    def test_sarif_shape(self):
        result = build_sarif(self.result(), "tools.json")
        self.assertEqual(result["version"], "2.1.0")
        item = result["runs"][0]["results"][0]
        self.assertEqual(item["level"], "error")
        self.assertEqual(item["properties"]["jsonPath"], "$.<x>")


if __name__ == "__main__":
    unittest.main()
