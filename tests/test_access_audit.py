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

from access_audit import audit_ssh_directory, audit_sshd_config, main, run_audit


class SshdConfigTests(unittest.TestCase):
    def test_flags_risky_options_case_insensitively(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "sshd_config"
            config.write_text(
                "# comment\nPermitRootLogin yes\nPermitEmptyPasswords yes\n"
                "PasswordAuthentication yes\nPubkeyAuthentication no\n",
                encoding="utf-8",
            )
            codes = {finding.code for finding in audit_sshd_config(config)}
            self.assertIn("SSHD_ROOT_LOGIN_ENABLED", codes)
            self.assertIn("SSHD_EMPTY_PASSWORDS_ALLOWED", codes)
            self.assertIn("SSHD_PASSWORD_AUTH_ENABLED", codes)
            self.assertIn("SSHD_PUBLIC_KEY_AUTH_DISABLED", codes)

    def test_first_value_wins_for_duplicate_directive(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "sshd_config"
            config.write_text("PermitRootLogin no\nPermitRootLogin yes\n", encoding="utf-8")
            codes = {finding.code for finding in audit_sshd_config(config)}
            self.assertNotIn("SSHD_ROOT_LOGIN_ENABLED", codes)

    def test_missing_config_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            findings = audit_sshd_config(Path(directory) / "missing.conf")
            self.assertEqual(findings[0].code, "SSHD_CONFIG_UNREADABLE")


class SshDirectoryTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX permission bits are required")
    def test_flags_exposed_private_key(self):
        with tempfile.TemporaryDirectory() as directory:
            ssh_dir = Path(directory) / ".ssh"
            ssh_dir.mkdir()
            key = ssh_dir / "id_ed25519"
            key.write_text("test-only placeholder", encoding="utf-8")
            key.chmod(0o644)
            codes = {finding.code for finding in audit_ssh_directory(ssh_dir)}
            self.assertIn("SSH_PRIVATE_KEY_PERMISSIONS", codes)

    @unittest.skipIf(os.name == "nt", "POSIX permission bits are required")
    def test_flags_writable_authorized_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            ssh_dir = Path(directory) / ".ssh"
            ssh_dir.mkdir()
            keys = ssh_dir / "authorized_keys"
            keys.write_text("ssh-ed25519 AAAA test", encoding="utf-8")
            keys.chmod(0o666)
            codes = {finding.code for finding in audit_ssh_directory(ssh_dir)}
            self.assertIn("SSH_AUTHORIZED_KEYS_WRITABLE", codes)

    def test_missing_directory_is_informational(self):
        with tempfile.TemporaryDirectory() as directory:
            findings = audit_ssh_directory(Path(directory) / "missing")
            self.assertEqual(findings[0].severity, "info")


class CliTests(unittest.TestCase):
    def test_json_output_is_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "sshd_config"
            config.write_text("PermitRootLogin yes\n", encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                status = main(["--sshd-config", str(config), "--json"])
            self.assertEqual(status, 0)
            parsed = json.loads(output.getvalue())
            self.assertEqual(parsed[0]["code"], "SSHD_ROOT_LOGIN_ENABLED")

    def test_audit_does_not_modify_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "sshd_config"
            original = "PermitRootLogin yes\n"
            config.write_text(original, encoding="utf-8")
            run_audit(config, None)
            self.assertEqual(config.read_text(encoding="utf-8"), original)


if __name__ == "__main__":
    unittest.main()
