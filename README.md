# AccessGuard: Local SSH Security Auditor

AccessGuard is a small, dependency-free Python tool for reviewing common SSH server configuration risks and local SSH key-file permission problems. It is designed for administrators auditing systems they own or are authorized to assess.

> **Safety and scope:** The original reverse-shell prototype has been retired. This repository no longer provides remote command execution, covert access, persistence, or remote file-transfer capabilities. AccessGuard is read-only: it reports findings and recommendations but does not change system settings or files.

## What it checks

- SSH server settings that can increase risk, including root login, empty passwords, password authentication, and disabled public-key authentication.
- Broad permissions on the selected SSH directory.
- Group/other access to common private-key filenames.
- Group/other write access to authorized_keys.
- Optional JSON output for automation and evidence capture.

This is a focused rules-based check, **not** a complete vulnerability scanner or a guarantee that a host is secure. It does not connect to remote hosts, enumerate networks, execute shell commands, or install services.

## Requirements

- Python 3.10 or later
- No third-party runtime dependencies

## Quick start

Run the default local checks (only targets that exist are selected automatically):

~~~bash
python3 access_audit.py
~~~

Explicitly inspect a configuration file and SSH directory:

~~~bash
python3 access_audit.py --sshd-config /etc/ssh/sshd_config --ssh-dir ~/.ssh
~~~

Print JSON for a pipeline or report collector:

~~~bash
python3 access_audit.py --sshd-config /etc/ssh/sshd_config --ssh-dir ~/.ssh --json
~~~

The tool does not require root for user-owned files. Some system configuration files may not be readable by your account; in that case it reports the issue instead of attempting privilege escalation.

## Interpreting findings

- **Critical / High:** investigate promptly; verify file ownership and access policy before changing permissions.
- **Medium:** review against your threat model and operational needs.
- **Low / Info:** informational or configuration-quality observations.

Recommendations are guidance, not automatic remediation. Changes to SSH access can lock you out; maintain an approved recovery path before applying them.

## Development and tests

Run the standard-library test suite:

~~~bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q access_audit.py backdoor.py tests
~~~

Continuous integration runs these checks on Python 3.10.

## Limitations

- The audit checks only the directives and file patterns listed above.
- SSH configuration includes advanced features (such as Match blocks and included files) that this small parser does not fully interpret. Review those manually.
- File ownership checks vary by platform; this version focuses on permission bits and does not claim complete cross-platform coverage.
- No automated remediation is performed.

## Security reporting

Please avoid posting secrets, private keys, passwords, or sensitive host details in public issues. See SECURITY.md for reporting guidance.
