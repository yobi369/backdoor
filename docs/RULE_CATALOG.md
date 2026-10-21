# AccessGuard Rule Catalogue

This catalogue describes the current implemented checks. It is deliberately explicit about coverage and limitations.

| Rule ID | Severity | Check | Important limitation |
|---|---|---|---|
| AG-SSH-001 | Info | sshd configuration cannot be read | Does not attempt privilege escalation |
| AG-SSH-002 | High | Global PermitRootLogin yes | Does not compute effective settings |
| AG-SSH-003 | Critical | Global PermitEmptyPasswords yes | Does not inspect authentication backend state |
| AG-SSH-004 | Medium | Global PasswordAuthentication yes | Policy depends on environment and compensating controls |
| AG-SSH-005 | Medium | Global PubkeyAuthentication no | Policy depends on supported authentication methods |
| AG-SSH-006 | Medium | Global PermitUserEnvironment yes | Does not inspect all authorized_keys options |
| AG-SSH-007 | Low | Global X11Forwarding yes | May be intentional on managed systems |
| AG-SSH-008 | Info | AllowUsers is configured | Does not verify the listed accounts |
| AG-SSH-009 | Info | Match block requires manual review | Conditional configuration is not evaluated |
| AG-SSH-010 | Info | Include pattern is unresolved, malformed, or unreadable | Relative patterns are resolved from the primary config directory; token expansion is not implemented |
| AG-SSH-011 | Low | Malformed global directive line | Syntax validation is not a substitute for sshd validation |
| AG-SSH-012 | Info | No active global directives | Empty configuration may rely on defaults or included files |
| AG-SSH-013 | Info | No checked global SSH directives flagged | Not a full SSH audit |\n| AG-SSH-014 | Info | Include cycle or expansion limit | Expansion is bounded; remaining files may be uninspected |
| AG-FS-001–006 | Info/Low | SSH path missing, wrong type, or unreadable | Permission checks depend on current process visibility |
| AG-FS-007 | Critical | Common private-key filename has group/other permissions | Filename heuristic; ownership and ACLs are not checked |
| AG-FS-008 | High | authorized_keys writable by group/others | Does not validate key content or ownership |
| AG-FS-009 | Info | No checked SSH permission issue | Limited check only |
| AG-HOST-001 | Critical | /etc/passwd writable by group/others | Selected path and mode bits only |
| AG-HOST-002 | High | /etc/shadow readable or writable by group/others | Distribution policy varies |
| AG-HOST-003 | High | /etc/sudoers writable by group/others | Does not validate sudo policy semantics |
| AG-HOST-004–005 | Info/Low | Policy path cannot be inspected or has unexpected type | Missing paths are skipped |
| AG-HOST-006 | Info | No checked host policy permission issue | Not a full host audit |
| AG-HOST-007 | High | sshd_config writable by group/others | Does not inspect included files |
| AG-HOST-008 | High | /etc/crontab writable by group/others | Does not inspect every scheduler or user crontab |
| AG-HOST-009 | High | /etc/cron.d writable by group/others | Directory mode bits only |
| AG-HOST-010 | High | /etc/sudoers.d writable by group/others | Directory mode bits only |

## Severity guidance

- Critical: a common permission or configuration weakness that can directly expose sensitive access material or account integrity.
- High: a configuration or permission weakness that may permit unauthorized changes or privileged access.
- Medium: an authentication or hardening setting requiring context-sensitive review.
- Low: a lower-priority hardening observation or configuration quality issue.
- Info: a scope, parsing, or context note.

Severity is not a CVSS score. Findings should be validated against the target system's policy, version, compensating controls, and operational requirements.

## Source-code heuristic rules

| Rule ID | Severity | Check | Important limitation |
|---|---|---|---|
| AG-CODE-001 | High | Python/JavaScript dynamic evaluation | Does not trace attacker-controlled data |
| AG-CODE-002 | High/Medium | Shell-based subprocess or JavaScript exec APIs | Does not perform taint analysis; context matters |
| AG-CODE-003 | High | Python os.system/os.popen usage | Does not prove the command is attacker-controlled |
| AG-CODE-004 | High | pickle/marshal deserialization APIs | Trust boundary and data provenance are not inferred |
| AG-CODE-005 | High | YAML loading without a recognized safe loader | PyYAML version and API context matter |
| AG-CODE-006 | High | TLS verification explicitly disabled | Library-specific configuration is not fully modeled |
| AG-CODE-007 | Medium | tempfile.mktemp usage | Requires code review for actual race exposure |
| AG-CODE-008 | Medium | innerHTML/dangerouslySetInnerHTML sinks | Does not trace sanitization or input provenance |
| AG-CODE-009 | High/Critical | Credential-like literals or private-key header | Heuristic may flag test fixtures; evidence redacts values |
| AG-CODE-010 | Info | Source file skipped, unreadable, or unparsable | Findings may be incomplete for that file |
| AG-CODE-011 | Info/Low | Source root cannot be safely inspected | Symlink roots are intentionally rejected |
| AG-CODE-012 | Info | No enabled source heuristics matched | Not evidence that the code is vulnerability-free |\n| AG-CODE-013 | High | Dynamically formatted Python/JavaScript SQL query | Does not trace data flow; query API and input provenance matter |

Source mode inspects Python, JavaScript, JSX, TypeScript, TSX, and selected JSON/YAML/TOML/INI/config files up to 1 MB each. Secret-pattern checks also include `.env` files. It skips common generated/dependency directories and does not follow symlinks. It does not scan dependencies, Git history, binaries, templates in other languages, or runtime behavior.
