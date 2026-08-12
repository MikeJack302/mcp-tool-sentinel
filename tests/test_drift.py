from copy import deepcopy
import unittest

from mcpsentinel.audit import audit_snapshot
from mcpsentinel.model import Policy
from test_audit import rules, snapshot


class DriftTests(unittest.TestCase):
    def test_description_change_and_unversioned_snapshot(self):
        baseline = snapshot()
        current = deepcopy(baseline)
        current["tools"][0]["description"] = "Changed model-facing description."
        result = rules(audit_snapshot(current, Policy(), baseline=baseline))
        self.assertIn("drift.description_changed", result)
        self.assertIn("drift.unversioned_snapshot", result)

    def test_version_change_recorded(self):
        baseline = snapshot()
        current = deepcopy(baseline)
        current["serverInfo"]["version"] = "1.1.0"
        self.assertIn("drift.server_version_changed", rules(audit_snapshot(current, Policy(), baseline=baseline)))

    def test_new_tool_blocked_or_allowed(self):
        baseline = snapshot()
        current = deepcopy(baseline)
        extra = deepcopy(current["tools"][0])
        extra["name"] = "read_other"
        current["tools"].append(extra)
        blocked = audit_snapshot(current, Policy(), baseline=baseline)
        item = next(entry for entry in blocked["findings"] if entry["rule_id"] == "drift.tool_added")
        self.assertEqual(item["severity"], "high")
        allowed = audit_snapshot(current, Policy(allow_new_tools=True), baseline=baseline)
        item = next(entry for entry in allowed["findings"] if entry["rule_id"] == "drift.tool_added")
        self.assertEqual(item["severity"], "low")

    def test_annotation_claims_safer(self):
        baseline = snapshot()
        baseline["tools"][0]["annotations"] = {"readOnlyHint": False, "destructiveHint": True,
                                                "idempotentHint": False, "openWorldHint": True}
        current = deepcopy(baseline)
        current["tools"][0]["annotations"] = {"readOnlyHint": True, "destructiveHint": False,
                                               "idempotentHint": True, "openWorldHint": False}
        items = [entry for entry in audit_snapshot(current, Policy(), baseline=baseline)["findings"]
                 if entry["rule_id"] == "drift.annotation_claims_safer"]
        self.assertEqual(len(items), 4)

    def test_annotation_risk_increased(self):
        baseline = snapshot()
        current = deepcopy(baseline)
        current["tools"][0]["annotations"] = {"readOnlyHint": False, "destructiveHint": True,
                                               "idempotentHint": False, "openWorldHint": True}
        self.assertIn("drift.annotation_risk_increased",
                      rules(audit_snapshot(current, Policy(), baseline=baseline)))

    def test_output_schema_removed(self):
        baseline = snapshot()
        current = deepcopy(baseline)
        del current["tools"][0]["outputSchema"]
        self.assertIn("drift.output_schema_removed", rules(audit_snapshot(current, Policy(), baseline=baseline)))

    def test_tool_order_change(self):
        baseline = snapshot()
        extra = deepcopy(baseline["tools"][0])
        extra["name"] = "read_second"
        baseline["tools"].append(extra)
        current = deepcopy(baseline)
        current["tools"].reverse()
        self.assertIn("drift.tool_order_changed", rules(audit_snapshot(current, Policy(), baseline=baseline)))

    def test_invalid_baseline_rejected(self):
        with self.assertRaisesRegex(ValueError, "baseline"):
            audit_snapshot(snapshot(), Policy(), baseline={"tools": [{"name": "x"}, {"name": "x"}]})


if __name__ == "__main__":
    unittest.main()
