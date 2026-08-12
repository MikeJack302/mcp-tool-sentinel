from pathlib import Path
import unittest

from mcpsentinel.audit import audit_snapshot
from mcpsentinel.model import Policy, load_json


ROOT = Path(__file__).parents[1]


class ExampleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = Policy.from_dict(load_json(ROOT / "examples" / "policy.json"))
        cls.baseline = load_json(ROOT / "examples" / "baseline-snapshot.json")
        cls.risky = load_json(ROOT / "examples" / "risky-snapshot.json")

    def test_baseline_is_clean(self):
        result = audit_snapshot(self.baseline, self.policy)
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["summary"]["findings"], 0)

    def test_risky_example_covers_supply_chain_rules(self):
        result = audit_snapshot(self.risky, self.policy, baseline=self.baseline)
        rules = {item["rule_id"] for item in result["findings"]}
        expected = {
            "header.sensitive_parameter", "content.prompt_injection", "content.embedded_secret",
            "schema.open_object", "drift.tool_added", "drift.description_changed",
            "schema.required_removed", "schema.upper_bound_relaxed", "schema.enum_expanded",
            "schema.pattern_weakened", "schema.additional_properties_opened", "schema.composition_changed",
            "drift.output_schema_removed", "drift.annotation_claims_safer",
        }
        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(expected <= rules, expected - rules)


if __name__ == "__main__":
    unittest.main()
