"""Regression corpus for security-relevant configuration cases.

These tests are deterministic fixtures, not a claim of real-world detection accuracy.
They lock in both detections and important scope boundaries.
"""
import tempfile
import unittest
from pathlib import Path

from access_audit import audit_sshd_config, render_sarif


class SSHRegressionCorpusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / "sshd_config"

    def write_config(self, text):
        self.config.write_text(text, encoding="utf-8")
        return self.config

    def ids(self, text):
        return {item.rule_id for item in audit_sshd_config(self.write_config(text))}

    def test_known_insecure_global_policy_is_detected(self):
        findings = audit_sshd_config(self.write_config(
            "PermitRootLogin yes\n"
            "PermitEmptyPasswords yes\n"
            "PasswordAuthentication yes\n"
            "PubkeyAuthentication no\n"
            "PermitUserEnvironment yes\n"
            "X11Forwarding yes\n"
        ))
        by_id = {item.rule_id: item for item in findings}
        self.assertTrue({
            "AG-SSH-002", "AG-SSH-003", "AG-SSH-004",
            "AG-SSH-005", "AG-SSH-006", "AG-SSH-007",
        }.issubset(by_id))
        self.assertEqual(by_id["AG-SSH-003"].severity, "critical")
        self.assertTrue(by_id["AG-SSH-003"].evidence)
        self.assertTrue(by_id["AG-SSH-003"].remediation)

    def test_hardened_global_policy_does_not_trigger_risky_value_rules(self):
        findings = audit_sshd_config(self.write_config(
            "PermitRootLogin no\n"
            "PermitEmptyPasswords no\n"
            "PasswordAuthentication no\n"
            "PubkeyAuthentication yes\n"
            "PermitUserEnvironment no\n"
            "X11Forwarding no\n"
        ))
        risky_ids = {"AG-SSH-002", "AG-SSH-003", "AG-SSH-004",
                     "AG-SSH-005", "AG-SSH-006", "AG-SSH-007"}
        self.assertTrue(risky_ids.isdisjoint({item.rule_id for item in findings}))

    def test_comment_and_blank_lines_do_not_create_directives(self):
        ids = self.ids(
            "# PermitRootLogin yes\n"
            "\n"
            "   # PermitEmptyPasswords yes\n"
            "PermitRootLogin no # reviewed policy\n"
        )
        self.assertNotIn("AG-SSH-002", ids)
        self.assertNotIn("AG-SSH-003", ids)

    def test_first_global_value_wins(self):
        ids = self.ids("PermitRootLogin no\nPermitRootLogin yes\n")
        self.assertNotIn("AG-SSH-002", ids)

    def test_conditional_match_block_is_explicitly_not_evaluated(self):
        findings = audit_sshd_config(self.write_config(
            "PermitRootLogin no\n"
            "Match User legacy-admin\n"
            "  PermitRootLogin yes\n"
        ))
        ids = {item.rule_id for item in findings}
        self.assertIn("AG-SSH-009", ids)
        # Do not misrepresent a conditional directive as a global finding.
        self.assertNotIn("AG-SSH-002", ids)

    def test_include_is_explicitly_reported_as_unexpanded(self):
        findings = audit_sshd_config(self.write_config(
            "Include /etc/ssh/sshd_config.d/*.conf\n"
            "PermitRootLogin no\n"
        ))
        include = next(item for item in findings if item.rule_id == "AG-SSH-010")
        self.assertIn("not expanded", include.description.lower())

    def test_sarif_rule_definitions_cover_every_result(self):
        findings = audit_sshd_config(self.write_config(
            "PermitRootLogin yes\n"
            "Match User contractor\n"
            "  PasswordAuthentication yes\n"
        ))
        sarif = render_sarif(findings)
        run = sarif["runs"][0]
        declared = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
        result_ids = {result["ruleId"] for result in run["results"]}
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertTrue(result_ids.issubset(declared))
        self.assertTrue(all(result.get("message", {}).get("text") for result in run["results"]))


if __name__ == "__main__":
    unittest.main()
