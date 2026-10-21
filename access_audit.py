"""Read-only local SSH and host-permission security auditor."""
from __future__ import annotations
import argparse, json, os, stat, sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {severity: index for index, severity in enumerate(SEVERITIES)}
RULES_VERSION = "1.1.0"

@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    description: str
    evidence: str = ""
    path: str | None = None
    remediation: str = ""
    references: tuple[str, ...] = ()

def finding(rule_id, severity, title, description, evidence="", path=None, remediation="", references=()):
    return Finding(rule_id, severity, title, description, evidence, str(path) if path is not None else None, remediation, references)

def _parse_global_sshd_options(path: Path):
    options, findings = {}, []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return {}, [finding("AG-SSH-001", "info", "SSH configuration could not be read",
            "The configuration file could not be inspected.", str(exc), path,
            "Check the path and read permissions.")]
    in_match = False
    for number, raw in enumerate(lines, 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        key = parts[0].lower()
        if key == "match":
            in_match = True
            findings.append(finding("AG-SSH-009", "info", "Conditional SSH configuration requires review",
                "A Match block was found; conditional rules are not evaluated.",
                f"Line {number}: {raw.strip()}", path,
                "Review each Match block and validate effective settings with OpenSSH.",
                ("https://man.openbsd.org/sshd_config",)))
            continue
        if key == "include":
            findings.append(finding("AG-SSH-010", "info", "Included SSH configuration requires review",
                "Included files are not expanded by this audit.",
                f"Line {number}: {raw.strip()}", path,
                "Review each included file and validate effective settings with OpenSSH.",
                ("https://man.openbsd.org/sshd_config",)))
            continue
        if in_match:
            continue
        if len(parts) != 2:
            findings.append(finding("AG-SSH-011", "low", "Malformed SSH configuration directive",
                "A non-comment line does not contain a directive and value.",
                f"Line {number}: {raw.strip()}", path, "Review against the sshd_config manual."))
            continue
        options.setdefault(key, parts[1].strip().lower())
    return options, findings

def audit_sshd_config(path: Path) -> list[Finding]:
    options, findings = _parse_global_sshd_options(path)
    if not options and not findings:
        return [finding("AG-SSH-012", "info", "No active global SSH directives",
            "No active global directives were found.", path=path)]
    checks = (
        ("permitrootlogin", "yes", "high", "AG-SSH-002", "SSH root login is enabled",
         "Set PermitRootLogin no unless a documented exception is required."),
        ("permitemptypasswords", "yes", "critical", "AG-SSH-003", "SSH permits empty passwords",
         "Set PermitEmptyPasswords no and verify authentication policy."),
        ("passwordauthentication", "yes", "medium", "AG-SSH-004", "SSH password authentication is enabled",
         "Prefer keys or an approved identity provider where practical; validate recovery access before changing."),
        ("pubkeyauthentication", "no", "medium", "AG-SSH-005", "SSH public-key authentication is disabled",
         "Enable public-key authentication if it is part of your access policy."),
        ("permituserenvironment", "yes", "medium", "AG-SSH-006", "SSH user environment processing is enabled",
         "Set PermitUserEnvironment no unless a reviewed requirement justifies it."),
        ("x11forwarding", "yes", "low", "AG-SSH-007", "SSH X11 forwarding is enabled",
         "Disable X11 forwarding where it is not required."),
    )
    for key, risky, severity, rule_id, title, remediation in checks:
        if options.get(key) == risky:
            findings.append(finding(rule_id, severity, title, f"The global {key} directive is set to '{risky}'.",
                f"{key} {risky}", path, remediation,
                ("https://man.openbsd.org/sshd_config",)))
    if "allowusers" in options:
        findings.append(finding("AG-SSH-008", "info", "SSH user allowlist is configured",
            "An AllowUsers directive restricts which accounts may log in.",
            f"AllowUsers {options['allowusers']}", path,
            "Confirm the allowlist is current and includes required recovery accounts."))
    if not findings:
        findings.append(finding("AG-SSH-013", "info", "No checked global SSH directives were flagged",
            "No risky values among checked directives were found.", path=path,
            remediation="This is not a complete assessment of effective SSH configuration."))
    return findings

def audit_ssh_directory(path: Path) -> list[Finding]:
    findings = []
    try:
        info = path.stat()
    except FileNotFoundError:
        return [finding("AG-FS-001", "info", "SSH directory not found",
            "No directory exists at the selected path.", path, "Pass --ssh-dir to inspect another location.")]
    except OSError as exc:
        return [finding("AG-FS-002", "info", "SSH directory could not be inspected",
            "Directory metadata could not be read.", str(exc), path)]
    if not stat.S_ISDIR(info.st_mode):
        return [finding("AG-FS-003", "low", "SSH path is not a directory",
            "The selected path is not a directory.", path=path)]
    if info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        findings.append(finding("AG-FS-004", "high", "SSH directory permissions are too broad",
            "Group or other users have permissions on the SSH directory.",
            f"Mode {stat.S_IMODE(info.st_mode):04o}", path,
            "Restrict the directory to its owner (commonly chmod 700) after checking ownership."))
    try:
        entries = tuple(path.iterdir())
    except OSError as exc:
        return findings + [finding("AG-FS-005", "info", "SSH directory contents could not be listed",
            "Directory entries could not be inspected.", str(exc), path)]
    for entry in entries:
        try:
            info = entry.lstat()
        except OSError as exc:
            findings.append(finding("AG-FS-006", "info", "SSH entry could not be inspected",
                "Metadata could not be read.", str(exc), entry))
            continue
        if not stat.S_ISREG(info.st_mode):
            continue
        mode, name = stat.S_IMODE(info.st_mode), entry.name.lower()
        private_key = ((name.startswith("id_") and not name.endswith(".pub")) or name in {"identity", "identity2"})
        if private_key and mode & (stat.S_IRWXG | stat.S_IRWXO):
            findings.append(finding("AG-FS-007", "critical", "Private SSH key is accessible by group or others",
                "A commonly named private key has group/other permission bits set.",
                f"Mode {mode:04o}", entry,
                "Restrict the private key to its owner (commonly chmod 600) and verify ownership."))
        if name == "authorized_keys" and mode & (stat.S_IWGRP | stat.S_IWOTH):
            findings.append(finding("AG-FS-008", "high", "authorized_keys is writable by group or others",
                "Another local account may be able to alter authorized SSH keys.",
                f"Mode {mode:04o}", entry,
                "Remove group/other write permission and verify ownership."))
    if not findings:
        findings.append(finding("AG-FS-009", "info", "No checked SSH permission issues were found",
            "The selected directory passed limited permission checks.", path=path,
            remediation="Ownership, ACLs, symlinks, and nonstandard key names are outside this check."))
    return findings

def audit_host_paths(root: Path) -> list[Finding]:
    findings = []
    checks = (
        ("etc/passwd", "AG-HOST-001", "critical", "Account database is writable by group or others",
         stat.S_IWGRP | stat.S_IWOTH, "Remove group/other write access and verify ownership."),
        ("etc/shadow", "AG-HOST-002", "high", "Shadow password database is accessible too broadly",
         stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH,
         "Restrict access according to the operating system account-management policy."),
        ("etc/sudoers", "AG-HOST-003", "high", "sudoers policy file is writable by group or others",
         stat.S_IWGRP | stat.S_IWOTH, "Remove group/other write access and validate policy with visudo."),
    )
    for relative, rule_id, severity, title, mask, remediation in checks:
        path = root / relative
        try:
            info = path.stat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            findings.append(finding("AG-HOST-004", "info", "Host policy file could not be inspected",
                str(exc), path=path))
            continue
        if not stat.S_ISREG(info.st_mode):
            findings.append(finding("AG-HOST-005", "low", "Expected host policy path is not a regular file",
                "The selected path does not refer to a regular file.", path=path))
            continue
        mode = stat.S_IMODE(info.st_mode)
        if mode & mask:
            findings.append(finding(rule_id, severity, title,
                "Permission bits exceed the expected conservative policy.",
                f"Mode {mode:04o}", path, remediation))
    if not findings:
        findings.append(finding("AG-HOST-006", "info", "No checked host policy permission issues were found",
            "Selected high-value policy files passed permission-bit checks.", path=root,
            remediation="ACLs, ownership, PAM, services, and other OS hardening settings are not assessed."))
    return findings

def load_baseline(path: Path) -> set[tuple[str, str | None]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    suppressions = data.get("suppressions", [])
    if not isinstance(suppressions, list):
        raise ValueError("baseline suppressions must be a list")
    result = set()
    for item in suppressions:
        if not isinstance(item, dict) or not isinstance(item.get("rule_id"), str):
            raise ValueError("each suppression must have a string rule_id")
        item_path = item.get("path")
        if item_path is not None and not isinstance(item_path, str):
            raise ValueError("suppression path must be a string or null")
        result.add((item["rule_id"], item_path))
    return result

def render_sarif(findings: list[Finding]) -> dict[str, Any]:
    rules, results = {}, []
    for item in findings:
        rule = {"id": item.rule_id, "name": item.title,
                "shortDescription": {"text": item.title},
                "fullDescription": {"text": item.description},
                "help": {"text": item.remediation or item.description},
                "properties": {"tags": ["security", "accessguard"], "severity": item.severity}}
        if item.references:
            rule["helpUri"] = item.references[0]
        rules.setdefault(item.rule_id, rule)
        level = "error" if item.severity in {"critical", "high"} else "warning" if item.severity == "medium" else "note"
        result = {"ruleId": item.rule_id, "level": level,
                  "message": {"text": item.description + (f" Evidence: {item.evidence}" if item.evidence else "")},
                  "properties": {"severity": item.severity}}
        if item.path:
            result["locations"] = [{"physicalLocation": {
                "artifactLocation": {"uri": item.path}, "region": {"startLine": 1}}}]
        results.append(result)
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "AccessGuard", "version": RULES_VERSION,
                "informationUri": "https://github.com/yobi369/backdoor", "rules": list(rules.values())}},
                "results": results}]}

def render_markdown(findings: list[Finding]) -> str:
    lines = ["# AccessGuard Security Audit", "", f"- Ruleset version: {RULES_VERSION}",
             f"- Findings: **{len(findings)}**", "", "| Severity | Rule | Finding | Location |",
             "|---|---|---|---|"]
    for item in findings:
        title = item.title.replace("|", "\\|")
        path = (item.path or "").replace("|", "\\|")
        lines.append(f"| {item.severity.upper()} | {item.rule_id} | {title} | {path} |")
    lines.extend(["", "## Details", ""])
    for item in findings:
        lines.extend([f"### {item.severity.upper()} — {item.title}", "",
            f"- Rule: {item.rule_id}", f"- Location: {item.path or 'not applicable'}",
            f"- Description: {item.description}"])
        if item.evidence:
            lines.append(f"- Evidence: {item.evidence}")
        if item.remediation:
            lines.append(f"- Recommendation: {item.remediation}")
        if item.references:
            lines.append("- References: " + ", ".join(item.references))
        lines.append("")
    lines.extend(["---", "This focused audit is not a full compliance assessment or a guarantee of security.", ""])
    return "\n".join(lines)

def render_text(findings: list[Finding]) -> str:
    lines = [f"AccessGuard {RULES_VERSION} — read-only local security audit"]
    for item in findings:
        location = f" [{item.path}]" if item.path else ""
        lines.append(f"[{item.severity.upper()}] {item.rule_id}: {item.title}{location}")
        lines.append(f"  {item.description}")
        if item.evidence:
            lines.append(f"  Evidence: {item.evidence}")
        if item.remediation:
            lines.append(f"  Recommendation: {item.remediation}")
    lines.append(f"\n{len(findings)} finding(s). Scope is limited; review findings in context.")
    return "\n".join(lines)

def run_audit(sshd_config: Path | None, ssh_dir: Path | None, host_root: Path | None = None) -> list[Finding]:
    findings = []
    if sshd_config is not None:
        findings.extend(audit_sshd_config(sshd_config))
    if ssh_dir is not None:
        findings.extend(audit_ssh_directory(ssh_dir))
    if host_root is not None:
        findings.extend(audit_host_paths(host_root))
    if not findings:
        findings.append(finding("AG-CLI-001", "info", "No audit targets selected",
            "Choose an SSH config, SSH directory, or --host-root."))
    return findings

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only local SSH and host-permission security audit.")
    parser.add_argument("--sshd-config", type=Path, help="Inspect sshd_config (read-only).")
    parser.add_argument("--ssh-dir", type=Path, help="Inspect a local SSH directory (read-only).")
    parser.add_argument("--host-root", type=Path, help="Inspect selected files beneath a Unix root; no recursive scan.")
    parser.add_argument("--format", choices=("text", "json", "markdown", "sarif"), default="text")
    parser.add_argument("--baseline", type=Path, help="JSON baseline of reviewed accepted findings.")
    parser.add_argument("--fail-on", choices=("none", "info", "low", "medium", "high", "critical"), default="none")
    parser.add_argument("--version", action="version", version=f"AccessGuard {RULES_VERSION}")
    args = parser.parse_args(argv)
    sshd_config, ssh_dir, host_root = args.sshd_config, args.ssh_dir, args.host_root
    if sshd_config is None and ssh_dir is None and host_root is None:
        config, sshdir = Path("/etc/ssh/sshd_config"), Path.home() / ".ssh"
        sshd_config = config if config.exists() else None
        ssh_dir = sshdir if sshdir.exists() else None
        host_root = Path("/") if os.name == "posix" and Path("/etc/passwd").exists() else None
    try:
        findings = run_audit(sshd_config, ssh_dir, host_root)
        if args.baseline:
            accepted = load_baseline(args.baseline)
            findings = [item for item in findings if (item.rule_id, item.path) not in accepted
                        and (item.rule_id, None) not in accepted]
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"AccessGuard: input error: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        output = json.dumps({"tool": "AccessGuard", "version": RULES_VERSION,
                             "findings": [asdict(item) for item in findings]}, indent=2)
    elif args.format == "sarif":
        output = json.dumps(render_sarif(findings), indent=2)
    elif args.format == "markdown":
        output = render_markdown(findings)
    else:
        output = render_text(findings)
    print(output)
    if args.fail_on != "none":
        threshold = SEVERITY_RANK[args.fail_on]
        if any(SEVERITY_RANK[item.severity] >= threshold for item in findings):
            return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
