"""Deterministic, evidence-backed AgentProof rules."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path, PurePosixPath

from .models import Finding, RuleMetadata, Severity

OWASP_LLM = "https://genai.owasp.org/llm-top-10/"
MCP_SECURITY = "https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices"


RULES: dict[str, RuleMetadata] = {
    "AP001": RuleMetadata(
        "AP001",
        "Hardcoded secret",
        Severity.CRITICAL,
        "secrets",
        "A credential-like value is stored directly in repository text.",
        "Revoke exposed credentials, remove them from Git history, and load secrets from an approved secret store or environment variable.",
        ("https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning",),
    ),
    "AP002": RuleMetadata(
        "AP002",
        "Remote script piped to a shell",
        Severity.HIGH,
        "supply-chain",
        "A remote response is executed without review or integrity verification.",
        "Download a version-pinned artifact, verify its checksum or signature, inspect it, then execute the local file.",
        ("https://slsa.dev/spec/v1.0/threats",),
    ),
    "AP003": RuleMetadata(
        "AP003",
        "Destructive or over-permissive command",
        Severity.HIGH,
        "execution",
        "An instruction or script contains a destructive filesystem command or grants broad permissions.",
        "Constrain the target path, require explicit confirmation, and use least-privilege permissions.",
        (OWASP_LLM,),
    ),
    "AP004": RuleMetadata(
        "AP004",
        "Instruction-boundary override",
        Severity.HIGH,
        "prompt-security",
        "Agent instructions attempt to suppress higher-priority policy or expose hidden prompts.",
        "Remove boundary-bypass language and define explicit, reviewable permissions instead.",
        (OWASP_LLM,),
    ),
    "AP005": RuleMetadata(
        "AP005",
        "Shell-backed MCP server",
        Severity.HIGH,
        "mcp",
        "An MCP server launches through a general-purpose command shell.",
        "Invoke a pinned executable directly and restrict arguments, environment variables, filesystem access, and network access.",
        (MCP_SECURITY,),
    ),
    "AP006": RuleMetadata(
        "AP006",
        "Wildcard MCP approval",
        Severity.HIGH,
        "mcp",
        "An MCP configuration automatically approves every tool or capability.",
        "Replace wildcard approval with an explicit allow-list and require user confirmation for sensitive operations.",
        (MCP_SECURITY,),
    ),
    "AP007": RuleMetadata(
        "AP007",
        "Insecure transport",
        Severity.MEDIUM,
        "transport",
        "A service URL uses plaintext HTTP or TLS verification is disabled.",
        "Use HTTPS, keep certificate validation enabled, and pin trusted endpoints where practical.",
        (MCP_SECURITY,),
    ),
    "AP008": RuleMetadata(
        "AP008",
        "Unpinned package execution",
        Severity.MEDIUM,
        "supply-chain",
        "A package runner can resolve a mutable latest version at execution time.",
        "Pin the package to an exact reviewed version and use a lockfile or integrity digest.",
        ("https://slsa.dev/spec/v1.0/threats",),
    ),
    "AP009": RuleMetadata(
        "AP009",
        "Incomplete skill metadata",
        Severity.LOW,
        "skills",
        "A SKILL.md file is missing machine-readable name or description metadata.",
        "Add YAML frontmatter containing a stable name and concise description.",
    ),
    "AP010": RuleMetadata(
        "AP010",
        "Unrestricted agent autonomy",
        Severity.HIGH,
        "permissions",
        "Agent instructions grant unrestricted command, filesystem, or confirmation bypass authority.",
        "Define bounded paths and commands, use least privilege, and require confirmation before irreversible or external actions.",
        (OWASP_LLM,),
    ),
    "AP011": RuleMetadata(
        "AP011",
        "Dynamic code execution",
        Severity.HIGH,
        "execution",
        "Potentially untrusted content is decoded or passed to a dynamic execution primitive.",
        "Use a typed parser and explicit command allow-list; never evaluate repository or network content as code.",
        (OWASP_LLM,),
    ),
    "AP012": RuleMetadata(
        "AP012",
        "Missing security policy",
        Severity.LOW,
        "project-quality",
        "The repository has no SECURITY.md vulnerability-reporting policy.",
        "Add SECURITY.md with supported versions and a private vulnerability reporting channel.",
        (
            "https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository",
        ),
    ),
    "AP013": RuleMetadata(
        "AP013",
        "Missing continuous integration",
        Severity.LOW,
        "project-quality",
        "No GitHub Actions workflow was found.",
        "Add CI that runs tests, linting, and AgentProof on every pull request.",
    ),
    "AP014": RuleMetadata(
        "AP014",
        "Missing license",
        Severity.LOW,
        "project-quality",
        "No recognized open-source license file was found.",
        "Choose an OSI-approved license and add it at the repository root.",
        ("https://choosealicense.com/",),
    ),
    "AP015": RuleMetadata(
        "AP015",
        "Missing automated tests",
        Severity.LOW,
        "project-quality",
        "No conventional automated-test directory or test file was found.",
        "Add deterministic tests for normal behavior, malicious fixtures, and report-schema stability.",
    ),
    "AP016": RuleMetadata(
        "AP016",
        "External symbolic link",
        Severity.MEDIUM,
        "filesystem",
        "A symbolic link resolves outside the repository boundary.",
        "Remove the link or make it resolve to a reviewed path inside the repository.",
        (OWASP_LLM,),
    ),
}


SECRET_PATTERNS = (
    re.compile(r"\b(?:gh[oprsu]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(
        r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|secret)\b"
        r"['\"]?\s*[:=]\s*['\"]([^'\"\s]{12,})['\"]"
    ),
)
PLACEHOLDERS = re.compile(
    r"(?i)(example|sample|placeholder|changeme|redacted|dummy|your[_-]|<[^>]+>|\$\{|process\.env|os\.environ|x{4,})"
)
REMOTE_PIPE = re.compile(r"(?i)\b(?:curl|wget)\b[^\n|]{0,300}\|\s*(?:sudo\s+)?(?:ba|z|fi)?sh\b")
DESTRUCTIVE = re.compile(
    r"(?i)(?:\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+(?:/|~|\$HOME)(?=[\s`'\"]|$)|\bchmod\s+(?:-R\s+)?777\b|"
    r"\b(?:format|mkfs(?:\.[a-z0-9]+)?)\s+(?:[a-z]:|/dev/)|\bDROP\s+(?:DATABASE|TABLE)\b)"
)
TLS_BYPASS = re.compile(
    r"(?i)(?:NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['\"]?0|verify\s*=\s*False|"
    r"\b(?:curl|wget)\b[^\n]{0,120}\s(?:-k|--insecure)\b)"
)
PROMPT_OVERRIDE = re.compile(
    r"(?i)(?:ignore\s+(?:all\s+)?(?:previous|prior|system|developer)\s+instructions|"
    r"reveal\s+(?:the\s+)?(?:system|developer)\s+prompt|bypass\s+(?:all\s+)?(?:safety|policy)|"
    r"disregard\s+(?:all\s+)?(?:previous|higher[- ]priority)\s+instructions)"
)
UNRESTRICTED = re.compile(
    r"(?i)(?:run\s+any\s+command|full\s+(?:filesystem|shell|system)\s+access|"
    r"without\s+(?:asking|user\s+confirmation|approval)|never\s+ask\s+for\s+confirmation|"
    r"write\s+(?:to\s+)?anywhere\s+on\s+(?:the\s+)?(?:disk|filesystem))"
)
DYNAMIC_EXECUTION = re.compile(
    r"(?i)(?:\beval\s*\(\s*(?:request|response|input|content|data)|"
    r"\bexec\s*\(\s*(?:request|response|input|content|data)|"
    r"base64\s+(?:--decode|-d)[^\n|]{0,120}\|\s*(?:ba|z|fi)?sh\b)"
)
UNPINNED_RUNNER = re.compile(r"(?i)\b(?:npx|uvx|pipx\s+run)\s+(?:--yes\s+)?([a-z0-9][a-z0-9_.\-/]*)(?:\s|$)")


AGENT_INSTRUCTION_PATHS = ("agents.md", "claude.md", ".github/copilot-instructions.md", "skill.md")
MCP_FILE_NAMES = {".mcp.json", "mcp.json", "claude_desktop_config.json"}


def all_rules() -> list[RuleMetadata]:
    return [RULES[key] for key in sorted(RULES)]


def is_agent_instruction(path: PurePosixPath) -> bool:
    lowered = path.as_posix().lower()
    return (
        path.name.lower() in AGENT_INSTRUCTION_PATHS
        or lowered.endswith("/skill.md")
        or "/.cursor/rules/" in f"/{lowered}"
        or lowered.startswith(".cursor/rules/")
    )


def is_mcp_config(path: PurePosixPath) -> bool:
    lowered = path.as_posix().lower()
    return path.name.lower() in MCP_FILE_NAMES or lowered.endswith(".mcp.json") or "/mcp/" in f"/{lowered}"


def _finding(
    rule_id: str, path: PurePosixPath, line: int, column: int, evidence: str, message: str
) -> Finding:
    rule = RULES[rule_id]
    clean_evidence = " ".join(evidence.strip().split())[:240]
    if rule_id == "AP001":
        clean_evidence = _redact(clean_evidence)
    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        category=rule.category,
        path=path.as_posix(),
        line=max(1, line),
        column=max(1, column),
        message=message,
        evidence=clean_evidence,
        remediation=rule.remediation,
        references=rule.references,
    )


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "[REDACTED]"
    return f"{value[:4]}…[REDACTED]…{value[-4:]}"


def _line_and_column(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    previous = text.rfind("\n", 0, offset)
    return line, offset - previous


def _regex_findings(
    rule_id: str,
    pattern: re.Pattern[str],
    path: PurePosixPath,
    text: str,
    message: str,
    *,
    ignore_placeholders: bool = False,
    ignore_negated: bool = False,
) -> Iterable[Finding]:
    for match in pattern.finditer(text):
        evidence = match.group(0)
        if ignore_placeholders and PLACEHOLDERS.search(evidence):
            continue
        if ignore_negated:
            prefix = text[max(0, match.start() - 40) : match.start()]
            if re.search(r"(?i)(?:do not|don't|never|must not|prohibited to)\b.{0,28}$", prefix):
                continue
        line, column = _line_and_column(text, match.start())
        yield _finding(rule_id, path, line, column, evidence, message)


def scan_text(path: PurePosixPath, text: str) -> list[Finding]:
    """Run content rules against a decoded text file."""

    findings: list[Finding] = []
    for pattern in SECRET_PATTERNS:
        findings.extend(
            _regex_findings(
                "AP001",
                pattern,
                path,
                text,
                "Credential-like material is committed as a literal value.",
                ignore_placeholders=True,
            )
        )
    findings.extend(
        _regex_findings(
            "AP002",
            REMOTE_PIPE,
            path,
            text,
            "Remote content is piped directly into a command shell.",
        )
    )
    findings.extend(
        _regex_findings(
            "AP003",
            DESTRUCTIVE,
            path,
            text,
            "Potentially destructive or over-permissive command detected.",
        )
    )
    findings.extend(
        _regex_findings(
            "AP007",
            TLS_BYPASS,
            path,
            text,
            "TLS certificate verification appears to be disabled.",
        )
    )
    findings.extend(
        _regex_findings(
            "AP011",
            DYNAMIC_EXECUTION,
            path,
            text,
            "Untrusted or externally supplied content may be executed dynamically.",
        )
    )

    if is_agent_instruction(path):
        findings.extend(
            _regex_findings(
                "AP004",
                PROMPT_OVERRIDE,
                path,
                text,
                "Agent-facing instructions contain a higher-priority instruction override.",
                ignore_negated=True,
            )
        )
        findings.extend(
            _regex_findings(
                "AP010",
                UNRESTRICTED,
                path,
                text,
                "Agent-facing instructions grant authority without a meaningful boundary.",
                ignore_negated=True,
            )
        )

    if is_mcp_config(path):
        findings.extend(
            _regex_findings(
                "AP008",
                UNPINNED_RUNNER,
                path,
                text,
                "MCP package runner does not pin an exact package version.",
            )
        )
        findings.extend(_scan_mcp_json(path, text))

    if path.name.lower() == "skill.md":
        findings.extend(_scan_skill_metadata(path, text))
    return _deduplicate(findings)


def _scan_mcp_json(path: PurePosixPath, text: str) -> list[Finding]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, dict):
        return []

    findings: list[Finding] = []
    servers = payload.get("mcpServers", payload.get("servers", {}))
    if isinstance(servers, dict):
        for server_name, config in servers.items():
            if not isinstance(config, dict):
                continue
            command = str(config.get("command", "")).lower()
            if Path(command).name in {"sh", "bash", "zsh", "fish", "cmd", "cmd.exe", "powershell", "pwsh"}:
                offset = text.find(str(config.get("command", "")))
                line, column = _line_and_column(text, max(0, offset))
                findings.append(
                    _finding(
                        "AP005",
                        path,
                        line,
                        column,
                        str(config.get("command", "")),
                        f"MCP server '{server_name}' is launched through a general-purpose shell.",
                    )
                )
            if Path(command).name in {"npx", "uvx", "pipx"}:
                args = config.get("args", [])
                if isinstance(args, list):
                    package = next(
                        (
                            str(item)
                            for item in args
                            if isinstance(item, str)
                            and item not in {"run", "--yes", "-y"}
                            and not item.startswith("-")
                        ),
                        "",
                    )
                    if package and not _package_is_pinned(package):
                        offset = text.find(package)
                        line, column = _line_and_column(text, max(0, offset))
                        findings.append(
                            _finding(
                                "AP008",
                                path,
                                line,
                                column,
                                package,
                                f"MCP server '{server_name}' executes an unpinned package.",
                            )
                        )
            url = config.get("url")
            if (
                isinstance(url, str)
                and url.lower().startswith("http://")
                and not url.lower().startswith("http://localhost")
            ):
                offset = text.find(url)
                line, column = _line_and_column(text, max(0, offset))
                findings.append(
                    _finding(
                        "AP007",
                        path,
                        line,
                        column,
                        url,
                        f"MCP server '{server_name}' uses plaintext HTTP transport.",
                    )
                )

    for key, value in _walk_items(payload):
        if key in {"autoApprove", "alwaysAllow", "allowedTools"} and (
            value == "*" or (isinstance(value, list) and "*" in value)
        ):
            offset = text.find(f'"{key}"')
            line, column = _line_and_column(text, max(0, offset))
            findings.append(
                _finding(
                    "AP006",
                    path,
                    line,
                    column,
                    f'"{key}": "*"',
                    f"MCP configuration grants wildcard approval through '{key}'.",
                )
            )
    return findings


def _package_is_pinned(package: str) -> bool:
    if "==" in package:
        name, version = package.rsplit("==", 1)
        return bool(name and version)
    if package.startswith("@"):
        slash = package.find("/")
        version_at = package.rfind("@")
        return slash > 1 and version_at > slash + 1 and version_at < len(package) - 1
    if "@" in package:
        name, version = package.rsplit("@", 1)
        return bool(name and version)
    return False


def _walk_items(value: object) -> Iterable[tuple[str, object]]:
    if isinstance(value, dict):
        for key, nested in value.items():
            yield str(key), nested
            yield from _walk_items(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk_items(nested)


def _scan_skill_metadata(path: PurePosixPath, text: str) -> list[Finding]:
    if not text.startswith("---\n"):
        return [
            _finding(
                "AP009",
                path,
                1,
                1,
                text.splitlines()[0] if text.splitlines() else "[empty file]",
                "SKILL.md has no YAML frontmatter.",
            )
        ]
    end = text.find("\n---", 4)
    if end < 0:
        return [_finding("AP009", path, 1, 1, "---", "SKILL.md frontmatter is not closed.")]
    frontmatter = text[4:end]
    missing = [key for key in ("name:", "description:") if key not in frontmatter.lower()]
    if not missing:
        return []
    return [
        _finding(
            "AP009",
            path,
            1,
            1,
            frontmatter[:160],
            f"SKILL.md frontmatter is missing: {', '.join(item.rstrip(':') for item in missing)}.",
        )
    ]


def repository_quality_findings(root: Path, relative_files: set[str]) -> list[Finding]:
    """Run repository-level engineering quality checks."""

    del root
    lower = {item.lower() for item in relative_files}
    findings: list[Finding] = []
    checks = (
        (
            "AP012",
            any(item == "security.md" or item == ".github/security.md" for item in lower),
            "SECURITY.md was not found.",
        ),
        (
            "AP013",
            any(item.startswith(".github/workflows/") and item.endswith((".yml", ".yaml")) for item in lower),
            "No GitHub Actions workflow was found.",
        ),
        (
            "AP014",
            any(
                PurePosixPath(item).name in {"license", "license.md", "license.txt", "copying"}
                for item in lower
            ),
            "No license file was found.",
        ),
        (
            "AP015",
            any("/test" in f"/{item}" or PurePosixPath(item).name.startswith("test_") for item in lower),
            "No automated tests were found.",
        ),
    )
    for rule_id, passed, message in checks:
        if not passed:
            findings.append(_finding(rule_id, PurePosixPath("."), 1, 1, "[repository metadata]", message))
    return findings


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    output: list[Finding] = []
    seen: set[tuple[str, str, int, str]] = set()
    for finding in findings:
        key = finding.fingerprint()
        if key not in seen:
            seen.add(key)
            output.append(finding)
    return output
