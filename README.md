# AccessGuard — Local Security Posture Auditor

AccessGuard is a dependency-free Python security engineering project for reviewing selected SSH configuration, SSH key-file permissions, and high-value Unix account-policy file permissions. It is intended for systems you own or are explicitly authorized to assess.

**Scope by design:** AccessGuard is read-only with respect to audited targets. It does not connect to remote hosts, execute shell commands, install services, establish persistence, or automatically remediate findings. Reports are printed to standard output; redirect them to save a report.

## Capabilities

- Stable rule IDs, severity ratings, evidence, remediation guidance, and references.
- Text, JSON, Markdown, and SARIF 2.1.0 report formats.
- Baseline suppressions for findings accepted by a team after review.
- CI-friendly fail-on severity thresholds.
- Checks for selected SSH daemon settings, SSH directory/private-key permissions, and selected Unix account-policy files.
- Unit tests and GitHub Actions validation.

## Requirements

- Python 3.10+
- No third-party runtime dependencies at runtime

## Install

From a cloned repository:

~~~bash
python3 -m pip install .
accessguard --version
~~~

Or run directly from the source checkout with Python.

## Quick start

Run default local checks:

~~~bash
accessguard
~~~

Audit explicit SSH files:

~~~bash
accessguard --sshd-config /etc/ssh/sshd_config --ssh-dir ~/.ssh
~~~

Run selected Unix host-policy checks:

~~~bash
accessguard --host-root /
~~~

Create machine-readable JSON or Markdown output:

~~~bash
accessguard --format json
accessguard --format markdown
~~~

Generate SARIF for supported reporting workflows:

~~~bash
accessguard --format sarif
~~~

Fail a CI step when a high-or-critical finding is present:

~~~bash
accessguard --fail-on high
~~~

Exit codes: 0 means the audit completed without crossing the selected threshold; 1 means the threshold was met; 2 means an input or baseline error occurred.

## Baselines

A baseline is a JSON file containing reviewed, accepted findings. Match both rule ID and path for a narrow suppression:

~~~json
{
  "suppressions": [
    {
      "rule_id": "AG-SSH-002",
      "path": "/etc/ssh/sshd_config"
    }
  ]
}
~~~

Then run:

~~~bash
accessguard --baseline baseline.json --format json
~~~

Treat baselines as reviewed security exceptions, not a way to hide unresolved risk. Keep them in version control and periodically reassess each exception.

## Tests

~~~bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q access_audit.py backdoor.py tests
~~~

GitHub Actions runs tests, compiles the source, installs the package, and smoke-tests the installed CLI and SARIF output.

## Rule scope and limitations

AccessGuard is a focused rules-based auditor, **not** a complete endpoint detection and response platform, vulnerability scanner, compliance certification, or guarantee of security.

- SSH Match blocks and Include files are flagged for manual review; effective OpenSSH configuration is not fully evaluated.
- Checks use filesystem permission bits. ACLs, ownership correctness, extended attributes, containers, service state, PAM, firewall state, kernel configuration, and network exposure are not comprehensively assessed.
- Host checks inspect only selected files and do not recursively scan the filesystem.
- Severity is a prioritization aid, not a formal risk score. Validate findings against the actual environment before making changes.
- The tool does not perform automatic remediation. Changes to SSH and account policy can lock out administrators; use an approved recovery path.

## Security reporting

Do not include credentials, private keys, access tokens, or sensitive host details in public issues. See SECURITY.md.

## Project direction

The goal is a transparent, testable, defensively focused security tool. Contributions should add documented rules, deterministic tests, evidence quality, platform-aware behavior, and clear false-positive handling.
