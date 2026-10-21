"""Read-only SSH access configuration auditor.

Inspects local SSH configuration and file permissions. It does not connect to
hosts, execute shell commands, modify files, or change settings.
"""
from __future__ import annotations

import argparse
import json
import stat
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    title: str
    detail: str
    path: str | None = None
    remediation: str = ""


def _effective_sshd_options(path: Path) -> tuple[dict[str, str], list[Finding]]:
    """Read the first occurrence of each sshd option, matching OpenSSH semantics."""
    options: dict[str, str] = {}
    findings: list[Finding] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return {}, [Finding("info", "SSHD_CONFIG_UNREADABLE",
                            "Could not read SSH server configuration",
                            str(exc), str(path),
                            "Run the audit with permission to read this file, if appropriate.")]

    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            findings.append(Finding(
                "low", "SSHD_CONFIG_MALFORMED", "Unrecognized SSH configuration line",
                f"Line {line_number} does not contain an option and value.",
                str(path), "Review the line against the sshd_config manual."
            ))
            continue
        key, value = parts[0].lower(), parts[1].strip().lower()
        options.setdefault(key, value)
    return options, findings


def audit_sshd_config(path: Path) -> list[Finding]:
    options, findings = _effective_sshd_options(path)
    if not options and not findings:
        return [Finding("info", "SSHD_CONFIG_EMPTY", "SSH configuration is empty",
                        "No active directives were found.", str(path),
                        "Confirm this is the intended configuration file.")]

    checks = (
        ("permitrootlogin", {"yes"}, "high", "Root SSH login is enabled",
         "Set PermitRootLogin no, or use a documented, tightly controlled exception."),
        ("permitemptypasswords", {"yes"}, "critical", "Empty SSH passwords are permitted",
         "Set PermitEmptyPasswords no."),
        ("passwordauthentication", {"yes"}, "medium", "SSH password authentication is enabled",
         "Prefer key-based authentication where practical; disable password authentication only after confirming recovery access."),
        ("pubkeyauthentication", {"no"}, "medium", "SSH public-key authentication is disabled",
         "Enable PubkeyAuthentication yes if key-based access is part of your access policy."),
        ("allowusers", set(), "info", "SSH user allowlist is configured",
         "Verify the listed accounts are current and intentional."),
    )
    for key, values, severity, title, remediation in checks:
        if key not in options:
            continue
        value = options[key]
        if key == "allowusers":
            findings.append(Finding(severity, "SSHD_ALLOWUSERS_SET", title,
                                    f"AllowUsers is set to: {value}", str(path), remediation))
        elif value in values:
            code = {
                "permitrootlogin": "SSHD_ROOT_LOGIN_ENABLED",
                "permitemptypasswords": "SSHD_EMPTY_PASSWORDS_ALLOWED",
                "passwordauthentication": "SSHD_PASSWORD_AUTH_ENABLED",
                "pubkeyauthentication": "SSHD_PUBLIC_KEY_AUTH_DISABLED",
            }[key]
            findings.append(Finding(severity, code, title,
                                    f"{key} is set to '{value}'.", str(path), remediation))
    if not findings:
        findings.append(Finding("info", "SSHD_NO_FLAGGED_OPTIONS",
                                "No checked SSH directives were flagged",
                                "This limited audit is not a complete security assessment.",
                                str(path), "Review the full SSH configuration and your access policy."))
    return findings


def audit_ssh_directory(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        info = path.stat()
    except FileNotFoundError:
        return [Finding("info", "SSH_DIR_NOT_FOUND", "SSH directory not found",
                        "No directory was found at the selected path.", str(path),
                        "Pass --ssh-dir to inspect a different location, if needed.")]
    except OSError as exc:
        return [Finding("info", "SSH_DIR_UNREADABLE", "Could not inspect SSH directory",
                        str(exc), str(path))]

    if not stat.S_ISDIR(info.st_mode):
        return [Finding("low", "SSH_PATH_NOT_DIRECTORY", "SSH path is not a directory",
                        "The selected path is not a directory.", str(path))]
    if info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        findings.append(Finding("high", "SSH_DIR_PERMISSIONS",
                                "SSH directory permissions are too broad",
                                f"Mode is {stat.S_IMODE(info.st_mode):04o}; group/other permissions are set.",
                                str(path), "Restrict the directory to its owner (commonly chmod 700)."))

    try:
        entries = tuple(path.iterdir())
    except OSError as exc:
        return findings + [Finding("info", "SSH_DIR_UNREADABLE",
                                   "Could not list SSH directory", str(exc), str(path))]

    for entry in entries:
        try:
            entry_info = entry.lstat()
        except OSError as exc:
            findings.append(Finding("info", "SSH_ENTRY_UNREADABLE",
                                    "Could not inspect SSH entry", str(exc), str(entry)))
            continue
        if not stat.S_ISREG(entry_info.st_mode):
            continue
        mode = stat.S_IMODE(entry_info.st_mode)
        name = entry.name.lower()
        is_private_key = (
            (name.startswith("id_") and not name.endswith(".pub"))
            or name in {"identity", "identity2"}
        )
        if is_private_key and mode & (stat.S_IRWXG | stat.S_IRWXO):
            findings.append(Finding("critical", "SSH_PRIVATE_KEY_PERMISSIONS",
                                    "Private SSH key is accessible by group or others",
                                    f"Mode is {mode:04o}.", str(entry),
                                    "Restrict the private key to its owner (commonly chmod 600)."))
        elif name == "authorized_keys" and mode & (stat.S_IWGRP | stat.S_IWOTH):
            findings.append(Finding("high", "SSH_AUTHORIZED_KEYS_WRITABLE",
                                    "authorized_keys can be modified by others",
                                    f"Mode is {mode:04o}.", str(entry),
                                    "Remove group/other write permission and verify file ownership."))
    if not findings:
        findings.append(Finding("info", "SSH_DIR_NO_FLAGGED_PERMISSIONS",
                                "No checked SSH permission issues were found",
                                "Only common SSH directory and key-file permission patterns were checked.",
                                str(path), "Review ownership and all SSH files as part of a broader audit."))
    return findings


def run_audit(sshd_config: Path | None, ssh_dir: Path | None) -> list[Finding]:
    findings: list[Finding] = []
    if sshd_config is not None:
        findings.extend(audit_sshd_config(sshd_config))
    if ssh_dir is not None:
        findings.extend(audit_ssh_directory(ssh_dir))
    if not findings:
        findings.append(Finding("info", "NO_TARGETS_SELECTED", "No audit targets selected",
                                "Choose --sshd-config and/or --ssh-dir."))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only local SSH configuration and permission audit."
    )
    parser.add_argument("--sshd-config", type=Path,
                        help="Path to sshd_config (not modified).")
    parser.add_argument("--ssh-dir", type=Path,
                        help="SSH directory to inspect (not modified).")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    args = parser.parse_args(argv)

    sshd_config = args.sshd_config
    ssh_dir = args.ssh_dir
    if sshd_config is None and ssh_dir is None:
        default_config = Path("/etc/ssh/sshd_config")
        default_ssh_dir = Path.home() / ".ssh"
        sshd_config = default_config if default_config.exists() else None
        ssh_dir = default_ssh_dir if default_ssh_dir.exists() else None

    findings = run_audit(sshd_config, ssh_dir)
    if args.json:
        print(json.dumps([asdict(item) for item in findings], indent=2))
    else:
        print("AccessGuard — local SSH audit (read-only)")
        for item in findings:
            location = f" [{item.path}]" if item.path else ""
            print(f"[{item.severity.upper()}] {item.title}{location}")
            print(f"  {item.detail}")
            if item.remediation:
                print(f"  Recommendation: {item.remediation}")
        print(f"\n{len(findings)} finding(s). This is a focused check, not a full security assessment.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
