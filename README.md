# AccessGuard — Local Security Posture Auditor

AccessGuard is a dependency-free Python security auditing tool for reviewing selected local SSH/host-policy settings and scanning Python, JavaScript, and TypeScript source for security-sensitive code patterns. It is intended for systems you own or are explicitly authorized to assess.

**Scope by design:** AccessGuard is read-only with respect to audited targets. It does not connect to remote hosts, execute shell commands, install services, establish persistence, or automatically remediate findings. Reports are printed to standard output; redirect them to save a report.

## Capabilities

- Stable rule IDs, severity ratings, evidence, remediation guidance, and references.
- Text, JSON, Markdown, and SARIF 2.1.0 report formats.
- Baseline suppressions for findings accepted by a team after review.
- CI-friendly fail-on severity thresholds.
- Checks for selected SSH daemon settings, SSH directory/private-key permissions, and selected Unix account-policy files.
- Conservative source-code checks for dynamic execution, shell invocation, unsafe deserialization/YAML loading, disabled TLS verification, risky HTML sinks, race-prone temporary files, and likely hard-coded credentials.
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

Audit a local source repository (Python, JavaScript, TypeScript):

~~~bash
accessguard --source-root /path/to/project --format sarif > accessguard.sarif
~~~

Source findings are static review candidates, not proof of exploitability. Source mode does not perform taint analysis, run code, fetch dependencies, or exploit the target.

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
python3 -m compileall -q access_audit.py source_audit.py backdoor.py tests
~~~

GitHub Actions runs tests, compiles the source, installs the package, and smoke-tests the installed CLI and SARIF output.

## Rule scope and limitations

AccessGuard is a focused rules-based auditor, **not** a complete endpoint detection and response platform, vulnerability scanner, compliance certification, or guarantee of security.

- SSH Include patterns are expanded with bounded recursion; Match blocks and OpenSSH token expansion are not fully evaluated, so effective settings still require platform validation.
- Source-code checks are conservative pattern/AST heuristics. They do not replace language-specific SAST, dependency auditing, secret-history scanning, dynamic testing, or manual review.
- Checks use filesystem permission bits. ACLs, ownership correctness, extended attributes, containers, service state, PAM, firewall state, kernel configuration, and network exposure are not comprehensively assessed.
- Host checks inspect only selected files and do not recursively scan the filesystem.
- Source-code checks are conservative pattern/AST heuristics. They do not replace language-specific SAST, dependency auditing, secret-history scanning, dynamic testing, or manual review.
- Severity is a prioritization aid, not a formal risk score. Validate findings against the actual environment before making changes.
- The tool does not perform automatic remediation. Changes to SSH and account policy can lock out administrators; use an approved recovery path.

## Security reporting

Do not include credentials, private keys, access tokens, or sensitive host details in public issues. See SECURITY.md.

## Project direction

The goal is a transparent, testable, defensively focused security tool. Contributions should add documented rules, deterministic tests, evidence quality, platform-aware behavior, and clear false-positive handling.


## Engineering and assurance documentation

- [Threat model](docs/THREAT_MODEL.md): assets, trust boundaries, in-scope threats, exclusions, and safe-operation notes.
- [Rule catalogue](docs/RULE_CATALOG.md): stable rule IDs, severity rationale, and limitations.
- [Security validation](docs/SECURITY_VALIDATION.md): regression corpus, test methodology, and limits on interpreting results.
- [Contributing guide](CONTRIBUTING.md): standards for rules, tests, and pull requests.
- Example fixtures: examples/sshd_config.sample and examples/baseline.json.
