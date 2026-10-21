import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from access_audit import main
from source_audit import audit_source_tree


class SourceAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_python_dangerous_calls_are_reported_with_lines(self):
        self.write("app.py", (
            "import subprocess\n"
            "import pickle\n"
            "import yaml\n"
            "import requests\n"
            "import tempfile\n"
            "result = eval(user_input)\n"
            "subprocess.run(command, shell=True)\n"
            "pickle.loads(payload)\n"
            "yaml.load(payload)\n"
            "requests.get(url, verify=False)\n"
            "tempfile.mktemp()\n"
        ))
        findings = audit_source_tree(self.root)
        by_id = {item.rule_id: item for item in findings}
        self.assertTrue({"AG-CODE-001", "AG-CODE-002", "AG-CODE-004",
                         "AG-CODE-005", "AG-CODE-006", "AG-CODE-007"}.issubset(by_id))
        self.assertEqual(by_id["AG-CODE-001"].line, 6)
        self.assertEqual(by_id["AG-CODE-002"].line, 7)
        self.assertEqual(by_id["AG-CODE-005"].severity, "high")

    def test_safe_yaml_loader_is_not_flagged(self):
        self.write("safe.py", "import yaml\nvalue = yaml.load(payload, Loader=yaml.SafeLoader)\n")
        findings = audit_source_tree(self.root)
        self.assertNotIn("AG-CODE-005", {item.rule_id for item in findings})

    def test_javascript_review_candidates_are_reported(self):
        path = self.write("src/app.ts", (
            "const output = eval(input);\n"
            "element.innerHTML = userValue;\n"
            "const client = { rejectUnauthorized: false };\n"
        ))
        findings = audit_source_tree(self.root)
        by_id = {item.rule_id: item for item in findings}
        self.assertTrue({"AG-CODE-001", "AG-CODE-006", "AG-CODE-008"}.issubset(by_id))
        self.assertEqual(by_id["AG-CODE-008"].path, str(path))
        self.assertEqual(by_id["AG-CODE-008"].line, 2)

    def test_literal_credentials_are_reported_without_exposing_value(self):
        self.write("settings.py", 'API_KEY = "this-is-a-real-looking-secret-value"\n')
        findings = audit_source_tree(self.root)
        secret = next(item for item in findings if item.rule_id == "AG-CODE-009")
        self.assertNotIn("this-is-a-real-looking-secret-value", secret.evidence)
        self.assertIn("redacted", secret.evidence.lower())

    def test_generated_and_dependency_directories_are_skipped(self):
        self.write("node_modules/pkg/index.js", "eval(userInput)\n")
        self.write("dist/bundle.js", "eval(userInput)\n")
        findings = audit_source_tree(self.root)
        self.assertNotIn("AG-CODE-001", {item.rule_id for item in findings})

    def test_sarif_uses_actual_source_line(self):
        path = self.write("app.py", "print('safe')\neval(user_input)\n")
        output = StringIO()
        with redirect_stdout(output):
            status = main(["--source-root", str(self.root), "--format", "sarif"])
        self.assertEqual(status, 0)
        sarif = json.loads(output.getvalue())
        result = next(item for item in sarif["runs"][0]["results"] if item["ruleId"] == "AG-CODE-001")
        location = result["locations"][0]["physicalLocation"]
        self.assertEqual(location["region"]["startLine"], 2)
        self.assertEqual(location["artifactLocation"]["uri"], str(path))

    def test_dynamic_sql_construction_is_reported_but_parameterized_query_is_not(self):
        self.write("db.py", (
            "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n"
            "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))\n"
        ))
        findings = audit_source_tree(self.root)
        sql_findings = [item for item in findings if item.rule_id == "AG-CODE-013"]
        self.assertEqual(len(sql_findings), 1)
        self.assertEqual(sql_findings[0].line, 1)

    def test_env_and_json_credentials_are_scanned_with_redacted_evidence(self):
        self.write(".env", "API_TOKEN=this-is-a-long-secret-value\n")
        self.write("settings.json", '{"password": "another-long-secret-value"}\n')
        findings = [item for item in audit_source_tree(self.root) if item.rule_id == "AG-CODE-009"]
        self.assertGreaterEqual(len(findings), 2)
        self.assertTrue(all("redacted" in item.evidence.lower() for item in findings))
        self.assertNotIn("this-is-a-long-secret-value", " ".join(item.evidence for item in findings))
        self.assertNotIn("another-long-secret-value", " ".join(item.evidence for item in findings))

    def test_source_root_must_be_a_real_directory(self):
        path = self.write("regular.py", "print('hello')\n")
        findings = audit_source_tree(path)
        self.assertEqual(findings[0].rule_id, "AG-CODE-011")


if __name__ == "__main__":
    unittest.main()
