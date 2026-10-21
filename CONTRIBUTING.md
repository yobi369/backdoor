# Contributing to AccessGuard

Thank you for helping improve AccessGuard.

## Principles

- Keep the default audit read-only with respect to audited targets.
- Never add covert access, persistence, credential collection, or remote command execution.
- Make every rule documented, deterministic, testable, and explicit about limitations.
- Prefer evidence-backed findings over vague warnings.
- Avoid making a recommendation that could lock out an administrator without a clear warning.

## Adding a rule

1. Assign a stable rule ID that is not already used.
2. Define the severity and explain why it is appropriate.
3. Include evidence and actionable remediation guidance.
4. Update docs/RULE_CATALOG.md and the README when scope changes.
5. Add positive and negative unit tests, including error-path coverage where practical.
6. Run the unit tests and compile check locally.
7. Describe false-positive considerations and platform assumptions in the pull request.

## Development checks

~~~bash
python3 -m compileall -q access_audit.py backdoor.py tests
python3 -m unittest discover -s tests -v
python3 access_audit.py --version
~~~

## Pull requests

Explain the problem, affected rule IDs, expected behavior, test evidence, platform scope, and known limitations. Do not include real secrets, private keys, or sensitive production host data in commits or issues.
