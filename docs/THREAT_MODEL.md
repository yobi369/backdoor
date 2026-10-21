# AccessGuard Threat Model

## Purpose

AccessGuard is a local, read-only security posture auditor. It reports a limited set of risky SSH settings and permission issues on selected SSH and Unix account-policy paths. It is not a remote administration agent, EDR, vulnerability scanner, or compliance certification product.

## Assets to protect

- Confidentiality of local SSH private keys and account policy data.
- Integrity of SSH authentication policy, sudo policy, and scheduled-task configuration.
- Integrity and trustworthiness of audit output.
- Operator understanding of what was and was not checked.

## Trust boundaries

- The operator chooses local paths and decides whether the machine is in scope.
- Filesystem metadata and file contents are treated as untrusted input.
- Baseline files are policy input and must be reviewed like code.
- Audit output may contain sensitive local paths and configuration evidence; handle reports accordingly.

## In-scope threats

- Common insecure global sshd directives explicitly checked by the rule set.
- Group/other permission exposure of commonly named private SSH keys.
- Group/other write access to authorized_keys.
- Group/other write access to selected Unix account, SSH, cron, and sudo policy paths.
- Malformed baseline input and invalid target paths causing crashes or misleading results.

## Out of scope

- Remote scanning, exploitation, credential collection, persistence, stealth, and command execution.
- Full effective OpenSSH configuration evaluation, including Match semantics and all OpenSSH token-expansion rules.
- ACLs, file ownership validation, SELinux/AppArmor policy, PAM, running service state, firewall configuration, kernel posture, container security, network exposure, and package vulnerabilities.
- Formal compliance attestation or guarantee that a host is secure.

## Security properties

- Read-only with respect to audited targets.
- No network sockets or shell command execution.
- No automatic remediation.
- Deterministic rule IDs and machine-readable output.
- Findings include scope caveats and practical remediation guidance.
- CI tests cover representative positive, negative, and input-error cases.

## Known limitations and mitigations

- The SSH parser expands bounded Include file patterns relative to the primary configuration directory. It reports unresolved patterns, cycles, and expansion limits; Match conditions and all OpenSSH token-expansion semantics are not evaluated.
- Permission checks inspect mode bits only and may miss ACL-based exposure or ownership problems.
- The scanner checks selected paths only and does not recursively walk the filesystem.
- Baseline suppressions can hide a known finding; keep baseline changes reviewed and narrowly scoped by rule ID and path.
- Severity is a prioritization label, not a quantitative risk score.

## Safe operation

Run only on systems you own or are authorized to audit. Review evidence before changing permissions or authentication settings. SSH changes can lock out administrators; keep a recovery path and test changes through an approved process.

## Reporting

Do not put secrets, private key contents, tokens, or sensitive host data in public issue reports. Follow SECURITY.md for reporting guidance.
