# Security Validation and Regression Corpus

## Purpose

AccessGuard's rule checks need repeatable tests for both positive detections and known-safe inputs. The automated regression corpus lives in `tests/test_security_regression.py` and runs in the same CI test command as the unit tests.

The corpus currently exercises:

- Known risky global SSH daemon settings and the expected severity/evidence/remediation fields.
- A hardened configuration that should not trigger those risky-value rules.
- Comments, blank lines, and OpenSSH's first-value-wins behavior for global options.
- Explicit disclosure that `Match` blocks are not evaluated.
- Include expansion, unresolved patterns, and cycle protection.
- Conservative Python/JavaScript/TypeScript source-code heuristic checks, dynamic SQL candidates, configuration secret redaction, and SARIF source-line mapping.
- SARIF 2.1.0 result-to-rule consistency.

## How to run

```bash
python -m unittest discover -s tests -v
coverage run --branch -m unittest discover -s tests -v
coverage report --fail-under=75
```

## Interpreting results

These are synthetic, deterministic regression fixtures. Passing them means the tested behaviors remain stable; it does **not** establish a real-world true-positive rate, false-positive rate, false-negative rate, or comprehensive operating-system coverage.

Before using AccessGuard to make production decisions, validate it against representative configurations from the target distributions and OpenSSH versions, compare findings with trusted platform tooling and manual review, and record misses and disagreements. Do not use absence of findings as proof that a host is secure.

## Next validation gates

1. Add isolated Linux integration tests across supported distributions and OpenSSH versions.
2. Test effective SSH policy with the platform's own validation facilities in a disposable environment; Include expansion still does not evaluate Match conditions or all OpenSSH token semantics.
3. Add permission/ownership/ACL cases and symlink edge cases, documenting platform-dependent expectations.
4. Build a reviewed benchmark set with expected results, track false positives and false negatives, and publish methodology with any reported metrics.
5. Obtain an independent security review before describing the tool as enterprise-ready.
