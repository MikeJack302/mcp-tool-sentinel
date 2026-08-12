import unittest

from mcpsentinel.model import Policy
from mcpsentinel.schema import audit_schema, compare_schemas


def closed_schema(properties=None, required=None):
    value = {"type": "object", "properties": properties or {}, "additionalProperties": False}
    if required is not None:
        value["required"] = required
    return value


def rules(findings):
    return {item["rule_id"] for item in findings}


class SchemaTests(unittest.TestCase):
    def audit(self, schema, policy=Policy(), is_input=True):
        return audit_schema(schema, tool_name="test", location="$.schema", is_input=is_input, policy=policy)[0]

    def test_secure_schema_passes(self):
        schema = closed_schema({"region": {"type": "string", "x-mcp-header": "Region"}}, ["region"])
        policy = Policy(allowed_header_names=("Region",))
        self.assertEqual(self.audit(schema, policy), [])

    def test_input_root_must_be_object(self):
        self.assertIn("schema.input_root_object", rules(self.audit({"type": "string"})))

    def test_open_input_object(self):
        self.assertIn("schema.open_object", rules(self.audit({"type": "object"})))

    def test_external_ref(self):
        schema = closed_schema({"x": {"$ref": "https://example.test/schema.json"}})
        self.assertIn("schema.external_ref", rules(self.audit(schema)))

    def test_header_name_and_allowlist(self):
        schema = closed_schema({"x": {"type": "string", "x-mcp-header": "bad header"}})
        self.assertIn("header.name_invalid", rules(self.audit(schema)))
        schema["properties"]["x"]["x-mcp-header"] = "Tenant"
        self.assertIn("header.not_allowed", rules(self.audit(schema)))

    def test_header_duplicate_is_case_insensitive(self):
        schema = closed_schema({
            "a": {"type": "string", "x-mcp-header": "Region"},
            "b": {"type": "string", "x-mcp-header": "region"},
        })
        policy = Policy(allowed_header_names=("Region",))
        self.assertIn("header.duplicate", rules(self.audit(schema, policy)))

    def test_sensitive_header(self):
        schema = closed_schema({"api_token": {"type": "string", "x-mcp-header": "Authorization"}})
        policy = Policy(allowed_header_names=("Authorization",))
        self.assertIn("header.sensitive_parameter", rules(self.audit(schema, policy)))

    def test_integer_header_needs_safe_bounds(self):
        schema = closed_schema({"count": {"type": "integer", "x-mcp-header": "Count"}})
        policy = Policy(allowed_header_names=("Count",))
        self.assertIn("header.integer_range", rules(self.audit(schema, policy)))

    def test_header_in_composition_not_statically_reachable(self):
        schema = closed_schema()
        schema["allOf"] = [{"type": "object", "properties": {
            "region": {"type": "string", "x-mcp-header": "Region"}}}]
        policy = Policy(allowed_header_names=("Region",))
        self.assertIn("header.not_statically_reachable", rules(self.audit(schema, policy)))

    def test_required_unknown_property(self):
        self.assertIn("schema.required_unknown", rules(self.audit(closed_schema({}, ["missing"]))))

    def test_nested_boolean_schema_is_valid(self):
        schema = closed_schema({"forbidden": False})
        self.assertEqual(self.audit(schema), [])

    def test_depth_limit_is_bounded(self):
        node = {"type": "string"}
        for _ in range(10):
            node = {"type": "array", "items": node}
        schema = closed_schema({"x": node})
        findings, metrics = audit_schema(schema, tool_name="x", location="$.schema", is_input=True,
                                         policy=Policy(max_schema_depth=4))
        self.assertIn("schema.depth_limit", rules(findings))
        self.assertLessEqual(metrics["max_depth"], 5)

    def test_semantic_widening(self):
        before = closed_schema({
            "amount": {"type": "integer", "minimum": 1, "maximum": 100},
            "mode": {"type": "string", "enum": ["safe"]},
        }, ["amount", "mode"])
        after = {"type": "object", "properties": {
            "amount": {"type": ["integer", "number"], "minimum": 0, "maximum": 1000},
            "mode": {"type": "string", "enum": ["safe", "admin"]},
        }, "required": ["amount"], "additionalProperties": True}
        result = rules(compare_schemas(before, after, location="$.input", is_input=True))
        expected = {"schema.type_widened", "schema.required_removed", "schema.lower_bound_relaxed",
                    "schema.upper_bound_relaxed", "schema.enum_expanded", "schema.additional_properties_opened"}
        self.assertTrue(expected <= result, expected - result)

    def test_header_and_pattern_drift(self):
        before = {"type": "string", "pattern": "^safe$"}
        after = {"type": "string", "x-mcp-header": "Route"}
        result = rules(compare_schemas(before, after, location="$.p", is_input=True))
        self.assertIn("schema.pattern_weakened", result)
        self.assertIn("schema.header_added", result)

    def test_boolean_schema_widening_is_critical(self):
        findings = compare_schemas(False, True, location="$.property", is_input=True)
        self.assertEqual(findings[0]["rule_id"], "schema.boolean_widened")
        self.assertEqual(findings[0]["severity"], "critical")

    def test_array_and_format_constraints_drift(self):
        before = {"type": "array", "uniqueItems": True, "items": {"type": "string", "format": "uuid"}}
        after = {"type": "array", "items": {"type": "string"}}
        result = rules(compare_schemas(before, after, location="$.array", is_input=True))
        self.assertIn("schema.uniqueness_removed", result)
        self.assertIn("schema.composition_changed", result)


if __name__ == "__main__":
    unittest.main()
