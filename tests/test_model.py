from pathlib import Path
import tempfile
import unittest

from mcpsentinel.model import Policy, load_json


class ModelTests(unittest.TestCase):
    def test_policy_lists_become_tuples(self):
        policy = Policy.from_dict({"allowed_header_names": ["Region"]})
        self.assertEqual(policy.allowed_header_names, ("Region",))

    def test_unknown_policy_field_rejected(self):
        with self.assertRaisesRegex(ValueError, "unknown"):
            Policy.from_dict({"surprise": True})

    def test_duplicate_casefolded_allowlist_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicates"):
            Policy.from_dict({"allowed_header_names": ["Region", "region"]})

    def test_strict_boolean(self):
        with self.assertRaisesRegex(ValueError, "allow_new_tools"):
            Policy.from_dict({"allow_new_tools": 1})

    def test_duplicate_json_key_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"tools": [], "tools": []}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                load_json(path)

    def test_nonfinite_json_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nan.json"
            path.write_text('{"value": NaN}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "non-finite"):
                load_json(path)


if __name__ == "__main__":
    unittest.main()
