# CrowdBug workflow integration

This guide describes how to use AccessGuard as a **local static-review stage** alongside CrowdBug. It does not assume a particular CrowdBug API or plugin interface: connect the stages using the orchestration hooks your CrowdBug setup actually supports.

## What each tool should do

- **AccessGuard:** read-only checks for selected local host-policy settings and source-code patterns; emits text, JSON, Markdown, or SARIF 2.1.0.
- **CrowdBug:** keep its existing authorized discovery, testing, and triage responsibilities.
- **Human review:** validate whether an AccessGuard candidate is reachable, exploitable, and relevant before changing code or reporting it as a vulnerability.

Do not treat a static pattern match as proof of exploitability, and do not treat a clean report as proof that a project is secure.

## Run it against a project you are authorized to assess

Install AccessGuard in a Python 3.10+ environment:

```bash
python -m venv .venv-accessguard
. .venv-accessguard/bin/activate
python -m pip install --upgrade pip
python -m pip install "git+https://github.com/yobi369/accessguard-auditor.git@master"
accessguard --version
```

For repeatable CI, pin the install to a reviewed commit SHA or a published, verified release rather than tracking `master`.

Run a source audit and retain machine-readable output:

```bash
accessguard --source-root /path/to/authorized/checkout --format json > accessguard-report.json
accessguard --source-root /path/to/authorized/checkout --format sarif > accessguard-report.sarif
```

For a CI gate that fails when high-or-critical findings are present:

```bash
accessguard --source-root /path/to/authorized/checkout --fail-on high
```

Exit codes: `0` means the chosen severity threshold was not met, `1` means it was met, and `2` indicates an input or baseline error. A threshold failure is a review gate, not proof that a vulnerability is exploitable.

## Suggested hand-off contract

When CrowdBug supports custom pipeline stages, pass a compact, stable record for each finding:

- `rule_id`, `severity`, `title`
- repository-relative `path` and optional `line`
- `description`, redacted `evidence`, `remediation`, and `references`
- scanner version, commit SHA, and scan timestamp supplied by the orchestrator

Use JSON for structured triage and SARIF when the receiving system supports SARIF. Preserve AccessGuard rule IDs so repeat runs can be compared. Deduplicate on at least scanner/rule ID, repository-relative path, and line where available; do not deduplicate solely on the title. Avoid uploading full source snippets or secrets to third-party systems.

## Recommended pipeline order

1. Check out the exact target commit and record its SHA.
2. Run AccessGuard on the checked-out source; archive JSON/SARIF as restricted build artifacts.
3. Run CrowdBug's authorized checks according to its own configuration and scope.
4. Normalize and deduplicate candidate findings without silently discarding evidence.
5. Triage candidates; verify data flow, reachability, and impact manually or with appropriate language-specific tooling.
6. Fail or block a release only according to an explicit team policy; retain the report and triage rationale.

## Safety and known limitations

- Only scan repositories and systems you own or have explicit permission to test.
- AccessGuard's source rules are pattern/AST heuristics, not full interprocedural taint analysis.
- It does not run target code, exploit findings, scan dependency vulnerabilities, or inspect full Git history for secrets.
- Reports can reveal repository paths and security-sensitive implementation details. Restrict artifact access and retention appropriately.
- No CrowdBug-specific adapter is included here because the exact CrowdBug API, event model, and report schema have not been verified. This guide provides a tool-level hand-off contract, not a claim of a tested native integration.
