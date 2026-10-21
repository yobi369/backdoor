import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from access_audit import audit_host_paths, audit_ssh_directory, audit_sshd_config, load_baseline, main, render_sarif, run_audit


class SshdConfigTests(unittest.TestCase):
    def test_flags_risky_options(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "sshd_config"
            config.write_text("PermitRootLogin yes\nPermitEmptyPasswords yes\nPasswordAuthentication yes\nPubkeyAuthentication no\nPermitUserEnvironment yes\n", encoding="utf-8")
            codes = {f.rule_id for f in audit_sshd_config(config)}
            self.assertTrue({"AG-SSH-002", "AG-SSH-003", "AG-SSH-004", "AG-SSH-005", "AG-SSH-006"}.issubset(codes))

    def test_first_value_wins(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "sshd_config"
            config.write_text("PermitRootLogin no\nPermitRootLogin yes\n", encoding="utf-8")
            self.assertNotIn("AG-SSH-002", {f.rule_id for f in audit_sshd_config(config)})

    def test_match_block_is_not_misread_as_global(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "sshd_config"
            config.write_text("Match User legacy\n  PermitRootLogin yes\n", encoding="utf-8")
            findings = audit_sshd_config(config)
            self.assertNotIn("AG-SSH-002", {f.rule_id for f in findings})
            self.assertIn("AG-SSH-009", {f.rule_id for f in findings})

    def test_include_is_flagged_for_manual_review(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "sshd_config"
            config.write_text("Include /etc/ssh/sshd_config.d/*.conf\n", encoding="utf-8")
            self.assertIn("AG-SSH-010", {f.rule_id for f in audit_sshd_config(config)})

    def test_missing_config_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            findings = audit_sshd_config(Path(directory) / "missing.conf")
            self.assertEqual(findings[0].rule_id, "AG-SSH-001")


class SshDirectoryTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX permission bits are required")
    def test_flags_exposed_private_key(self):
        with tempfile.TemporaryDirectory() as directory:
            ssh_dir = Path(directory) / ".ssh"
            ssh_dir.mkdir()
            key = ssh_dir / "id_ed25519"
            key.write_text("test-only placeholder", encoding="utf-8")
            key.chmod(0o644)
            self.assertIn("AG-FS-007", {f.rule_id for f in audit_ssh_directory(ssh_dir)})

    @unittest.skipIf(os.name == "nt", "POSIX permission bits are required")
    def test_flags_writable_authorized_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            ssh_dir = Path(directory) / ".ssh"
            ssh_dir.mkdir()
            keys = ssh_dir / "authorized_keys"
            keys.write_text("ssh-ed25519 AAAA test", encoding="utf-8")
            keys.chmod(0o666)
            self.assertIn("AG-FS-008", {f.rule_id for f in audit_ssh_directory(ssh_dir)})

    def test_missing_directory_is_informational(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(audit_ssh_directory(Path(directory) / "missing")[0].severity, "info")


class HostPathTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX permission bits are required")
    def test_flags_writable_passwd(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc").mkdir()
            passwd = root / "etc" / "passwd"
            passwd.write_text("root:x:0:0:root:/root:/bin/sh\n", encoding="utf-8")
            passwd.chmod(0o666)
            self.assertIn("AG-HOST-001", {f.rule_id for f in audit_host_paths(root)})

    def test_missing_host_files_do_not_crash(self):
        with tempfile.TemporaryDirectory() as directory:
            findings = audit_host_paths(Path(directory))
            self.assertTrue(findings)
            self.assertTrue(all(f.severity == "info" for f in findings))

    @unittest.skipIf(os.name == "nt", "POSIX permission bits are required")
    def test_flags_writable_ssh_daemon_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc" / "ssh").mkdir(parents=True)
            config = root / "etc" / "ssh" / "sshd_config"
            config.write_text("PermitRootLogin no\\n", encoding="utf-8")
            config.chmod(0o666)
            self.assertIn("AG-HOST-007", {f.rule_id for f in audit_host_paths(root)})

    @unittest.skipIf(os.name == "nt", "POSIX permission bits are required")
    def test_flags_writable_cron_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc" / "cron.d").mkdir(parents=True)
            (root / "etc" / "cron.d").chmod(0o777)
            self.assertIn("AG-HOST-009", {f.rule_id for f in audit_host_paths(root)})


class ReportingTests(unittest.TestCase):
    def test_json_output_is_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "sshd_config"
            config.write_text("PermitRootLogin yes\n", encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                status = main(["--sshd-config", str(config), "--format", "json"])
            self.assertEqual(status, 0)
            self.assertEqual(json.loads(output.getvalue())["findings"][0]["rule_id"], "AG-SSH-002")

    def test_sarif_schema_version(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "sshd_config"
            config.write_text("PermitRootLogin yes\n", encoding="utf-8")
            sarif = render_sarif(audit_sshd_config(config))
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "AG-SSH-002")

    def test_markdown_output_contains_remediation(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "sshd_config"
            config.write_text("PermitRootLogin yes\n", encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                status = main(["--sshd-config", str(config), "--format", "markdown"])
            self.assertEqual(status, 0)
            self.assertIn("Recommendation", output.getvalue())

    def test_fail_on_threshold(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "sshd_config"
            config.write_text("PermitRootLogin yes\n", encoding="utf-8")
            with redirect_stdout(StringIO()):
                status = main(["--sshd-config", str(config), "--fail-on", "high"])
            self.assertEqual(status, 1)

    def test_baseline_suppresses_matching_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "sshd_config"
            config.write_text("PermitRootLogin yes\n", encoding="utf-8")
            baseline = root / "baseline.json"
            baseline.write_text(json.dumps({"suppressions": [{"rule_id": "AG-SSH-002", "path": str(config)}]}), encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                status = main(["--sshd-config", str(config), "--baseline", str(baseline), "--format", "json"])
            self.assertEqual(status, 0)
            self.assertEqual(json.loads(output.getvalue())["findings"], [])

    def test_invalid_baseline_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            baseline = Path(directory) / "baseline.json"
            baseline.write_text('{"suppressions": "not a list"}', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_baseline(baseline)

    def test_audit_does_not_modify_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "sshd_config"
            original = "PermitRootLogin yes\n"
            config.write_text(original, encoding="utf-8")
            run_audit(config, None)
            self.assertEqual(config.read_text(encoding="utf-8"), original)


if __name__ == "__main__":
    unittest.main()
