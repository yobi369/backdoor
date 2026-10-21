# Changelog

All notable changes to AccessGuard are documented here. This project follows a pragmatic versioning scheme; releases are not a guarantee of comprehensive security coverage.

## [1.2.1] - 2026-10-21

### Fixed
- Correct credential-placeholder handling in source-code heuristics so recognized examples such as `your_api_key` and `replace_me` are suppressed consistently.
- Detect simple JavaScript/TypeScript SQL string concatenation as a review candidate, alongside template interpolation.
- Clarify SQL heuristic evidence to avoid implying that a pattern match proves exploitability.

### Added
- Regression tests for credential placeholders and concatenated versus parameterized JavaScript SQL calls.
- CrowdBug workflow integration guidance covering JSON/SARIF hand-off, severity gates, triage, and report handling.

### Validation
- GitHub Actions tests, lint checks, branch-coverage threshold, package installation, CLI smoke checks, and portable JSON self-audit run on Python 3.10, 3.11, 3.12, and 3.13.

### Limitations
- Source analysis remains heuristic; no full interprocedural taint analysis is performed.
- Dependency vulnerability scanning, Git-history secret scanning, and a representative external false-positive/false-negative benchmark are not included in this release.
- The CrowdBug document describes a tool-level workflow, not a native adapter verified against a CrowdBug API.
