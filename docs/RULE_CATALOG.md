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
| AG-SSH-010 | Info | Include directive requires manual review | Included files are not expanded |
| AG-SSH-011 | Low | Malformed global directive line | Syntax validation is not a substitute for sshd validation |
| AG-SSH-012 | Info | No active global directives | Empty configuration may rely on defaults or included files |
| AG-SSH-013 | Info | No checked global SSH directives flagged | Not a full SSH audit |
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
