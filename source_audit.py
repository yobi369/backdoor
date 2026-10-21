"""Conservative, dependency-free source-code security checks.

These heuristics identify review candidates; they do not perform taint analysis
or prove exploitability. Evidence is redacted where it may contain a secret.
"""
from __future__ import annotations

import ast
import os
import re
import stat
from pathlib import Path

from access_audit import Finding, finding

SUPPORTED_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf"}
SKIP_DIRECTORIES = {
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "dist", "build",
    "coverage", ".tox", ".mypy_cache", ".pytest_cache", "__pycache__",
}
MAX_SOURCE_BYTES = 1_000_000
SECRET_ASSIGNMENT = re.compile(
    r"""\b(?:api[_-]?(?:key|token)|secret(?:[_-]?key)?|password|passwd|access[_-]?token|auth[_-]?token)\b["']?\s*[:=]\s*(?:(['"])(?P<quoted>[^'"\n]{8,})\1|(?P<bare>[A-Za-z0-9_./+=-]{12,}))""",
    re.IGNORECASE,
)
PLACEHOLDER_VALUES = {
    "changeme", "change_me", "example", "placeholder", "your_token_here",
    "your_api_key", "redacted", "dummy", "test", "testing", "none", "null",
}


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _is_false_literal(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _python_findings(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError as exc:
        return [finding("AG-CODE-010", "info", "Python source could not be parsed",
            "Syntax parsing failed, so AST-based checks were skipped for this file.",
            f"Line {exc.lineno or 1}: {exc.msg}", path,
            "Fix syntax errors or review this file manually.", line=exc.lineno)]

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node.func)
        line = getattr(node, "lineno", None)
        if name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
            findings.append(finding("AG-CODE-001", "high", "Dynamic code execution call",
                "eval/exec can execute attacker-controlled code when input reaches this call; data flow is not assessed.",
                f"Call to {name}", path, "Avoid dynamic evaluation; use a constrained parser or explicit dispatch.", line=line))
        if name in {"os.system", "os.popen"}:
            findings.append(finding("AG-CODE-003", "high", "Shell command execution API used",
                "Shell execution can become command injection if untrusted input reaches the command string.",
                f"Call to {name}", path, "Prefer argument-list subprocess APIs and validate any externally influenced arguments.", line=line))
        if name in {"subprocess.run", "subprocess.Popen", "subprocess.call",
                    "subprocess.check_call", "subprocess.check_output"}:
            shell_true = any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant)
                             and keyword.value.value is True for keyword in node.keywords)
            if shell_true:
                findings.append(finding("AG-CODE-002", "high", "Subprocess invoked with shell=True",
                    "A shell parses the command string; attacker-controlled interpolation can enable command injection.",
                    f"Call to {name} with shell=True", path,
                    "Use an argument list with shell=False and validate arguments.", line=line))
        if name in {"pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads",
                    "marshal.load", "marshal.loads"}:
            findings.append(finding("AG-CODE-004", "high", "Unsafe deserialization API used",
                "Deserializing untrusted pickle/marshal data can execute code or corrupt application state.",
                f"Call to {name}", path, "Do not deserialize untrusted data with pickle or marshal; use a safe data format.", line=line))
        if name in {"yaml.load", "yaml.unsafe_load"}:
            loader = next((kw.value for kw in node.keywords if kw.arg == "Loader"), None)
            loader_name = _call_name(loader) if loader is not None else ""
            safe_loader = loader_name.endswith(("SafeLoader", "CSafeLoader"))
            if not safe_loader:
                findings.append(finding("AG-CODE-005", "high", "Potentially unsafe YAML loader",
                    "yaml.load without an explicit safe loader may construct arbitrary Python objects, depending on PyYAML version and configuration.",
                    f"Call to {name}; loader={loader_name or 'implicit/default'}", path,
                    "Use yaml.safe_load or explicitly use yaml.SafeLoader after verifying the installed PyYAML version.", line=line))
        if name.startswith(("requests.", "httpx.")) or name in {"urllib3.PoolManager.request"}:
            if any(keyword.arg == "verify" and _is_false_literal(keyword.value) for keyword in node.keywords):
                findings.append(finding("AG-CODE-006", "high", "TLS certificate verification disabled",
                    "Disabling TLS verification can expose connections to interception; the target library's API is context-dependent.",
                    f"Call to {name} with verify=False", path,
                    "Keep certificate verification enabled and configure trusted CA certificates instead.", line=line))
        if name == "tempfile.mktemp":
            findings.append(finding("AG-CODE-007", "medium", "Race-prone temporary filename API used",
                "mktemp returns a name without securely creating the file, creating a race window.",
                "Call to tempfile.mktemp", path, "Use NamedTemporaryFile or another atomic temporary-file API.", line=line))
        if name.endswith((".execute", ".executemany", ".query")) and node.args:
            query = node.args[0]
            formatted_query = isinstance(query, (ast.JoinedStr, ast.BinOp))
            if isinstance(query, ast.Call) and _call_name(query.func).endswith(".format"):
                formatted_query = True
            if formatted_query:
                findings.append(finding("AG-CODE-013", "high", "Potential SQL query built dynamically",
                    "A query/execute call receives a formatted or concatenated expression; SQL injection depends on the database API and input provenance.",
                    f"Dynamic query expression passed to {name}", path,
                    "Use parameterized queries for values and allowlist any dynamic identifiers.", line=line))

    return findings


def _line_findings(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "*")):
            continue
        if path.suffix.lower() in {".js", ".jsx", ".ts", ".tsx"}:
            if re.search(r"\beval\s*\(|\bnew\s+Function\s*\(", line):
                findings.append(finding("AG-CODE-001", "high", "Dynamic code execution call",
                    "eval/new Function can execute attacker-controlled code; data flow is not assessed.",
                    "Dynamic evaluation syntax detected", path,
                    "Avoid dynamic evaluation and use explicit parsing or dispatch.", line=number))
            if re.search(r"\b(?:child_process\.)?(?:exec|execSync)\s*\(", line):
                findings.append(finding("AG-CODE-002", "medium", "Shell command execution API used",
                    "Shell-based command execution deserves review if arguments can be influenced by users.",
                    "Potential shell execution call; argument data flow is not assessed", path,
                    "Prefer argument-array APIs such as execFile/spawn with shell disabled.", line=number))
            if re.search(r"\bdangerouslySetInnerHTML\b|\.innerHTML\s*=", line):
                findings.append(finding("AG-CODE-008", "medium", "Potentially unsafe HTML injection sink",
                    "Direct HTML insertion can create XSS if the inserted value is untrusted or insufficiently sanitized.",
                    "HTML insertion sink detected; input trust is not assessed", path,
                    "Prefer text rendering; sanitize trusted HTML with a well-maintained sanitizer.", line=number))
            if re.search(r"\b(?:rejectUnauthorized|strictSSL|verify)\s*:\s*false\b", line):
                findings.append(finding("AG-CODE-006", "high", "TLS certificate verification may be disabled",
                    "A false TLS-verification option can allow intercepted connections; library context is not inferred.",
                    "TLS verification option set to false", path,
                    "Keep certificate verification enabled and configure trusted CA certificates.", line=number))
            if re.search(r"\b(?:query|execute)\s*\(\s*\x60[^\x60]*\$\{", line):
                findings.append(finding("AG-CODE-013", "high", "Potential SQL query built dynamically",
                    "A query/execute call appears to use template interpolation; SQL injection depends on API and input provenance.",
                    "Interpolated template passed to query/execute; data flow is not assessed", path,
                    "Use parameterized queries for values and allowlist any dynamic identifiers.", line=number))

        secret_match = SECRET_ASSIGNMENT.search(line)
        if secret_match:
            value = (secret_match.group("quoted") or secret_match.group("bare") or "").strip()
            normalized = value.lower().replace("-", "_").replace(" ", "_")
            placeholder = normalized in PLACEHOLDER_VALUES or normalized.startswith(
                ("your_", "example_", "placeholder_", "replace_me")
            )
            if not placeholder and not (value.startswith(") and value.endswith(")):
                findings.append(finding("AG-CODE-009", "high", "Possible hard-coded credential",
                    "A credential-like assignment contains a literal value; this heuristic may flag test fixtures and requires review.",
                    "Credential-like value detected; literal redacted", path,
                    "Move real credentials to a secret manager or environment configuration, and rotate exposed credentials.", line=number))
        if "-----BEGIN " in line and "PRIVATE KEY-----" in line:
            findings.append(finding("AG-CODE-009", "critical", "Private key material appears in source",
                "A private-key PEM header was found in a source file.",
                "Private key content redacted", path,
                "Remove the key from source history, rotate it, and use a secret manager.", line=number))
    return findings


def audit_source_tree(root: Path) -> list[Finding]:
    """Scan supported source files without following symlinks or modifying targets."""
    root = Path(root)
    try:
        info = root.lstat()
    except OSError as exc:
        return [finding("AG-CODE-011", "info", "Source root could not be inspected",
            "The selected source path could not be inspected.", str(exc), root,
            "Check the path and permissions.")]
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        return [finding("AG-CODE-011", "low", "Source root is not a real directory",
            "The selected source root must be a directory, not a symlink or regular file.",
            path=root, remediation="Select a real local source directory.")]

    findings: list[Finding] = []
    for current, directories, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        directories[:] = sorted(
            name for name in directories
            if name not in SKIP_DIRECTORIES and not (current_path / name).is_symlink()
        )
        for filename in sorted(filenames):
            path = current_path / filename
            is_env_file = path.name == ".env" or path.name.startswith(".env.")
            if (path.suffix.lower() not in SUPPORTED_SUFFIXES and not is_env_file) or path.is_symlink():
                continue
            try:
                file_info = path.stat()
                if not stat.S_ISREG(file_info.st_mode):
                    continue
                if file_info.st_size > MAX_SOURCE_BYTES:
                    findings.append(finding("AG-CODE-010", "info", "Source file skipped due to size",
                        f"The file exceeds the {MAX_SOURCE_BYTES}-byte analysis limit.",
                        path=path.relative_to(root), remediation="Review this file manually or split generated/vendor content."))
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                findings.append(finding("AG-CODE-010", "info", "Source file could not be inspected",
                    "The file could not be read; checks were skipped.", str(exc), path.relative_to(root),
                    "Check file permissions and inspect this file manually."))
                continue
            if path.suffix.lower() == ".py":
                findings.extend(_python_findings(path.relative_to(root), text))
            findings.extend(_line_findings(path.relative_to(root), text))

    if not findings:
        findings.append(finding("AG-CODE-012", "info", "No source-code heuristic findings",
            "No enabled patterns matched the supported source files.",
            remediation="This is not proof of absence of vulnerabilities; review coverage and dependencies."))
    return findings
