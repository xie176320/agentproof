"""Terminal, JSON, Markdown, HTML, and SARIF report generation."""

from __future__ import annotations

import json
from html import escape
from typing import Any

from .models import Finding, ScanResult, Severity
from .rules import RULES

COLORS = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[2m",
}
RESET = "\033[0m"


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def terminal_report(result: ScanResult, *, color: bool = True) -> str:
    counts = result.counts
    lines = [
        f"AgentProof score: {result.score}/100 ({_grade(result.score)})",
        f"Security: {result.security_score}/100 | Engineering quality: {result.quality_score}/100",
        (
            f"Findings: {counts['critical']} critical, {counts['high']} high, "
            f"{counts['medium']} medium, {counts['low']} low"
        ),
        f"Scanned {result.files_scanned} text files in {result.duration_ms} ms",
    ]
    if not result.findings:
        lines.append("\nNo findings. Static analysis cannot prove a repository is risk-free.")
        return "\n".join(lines)

    lines.append("")
    for item in result.findings:
        severity = item.severity.label().upper()
        if color:
            severity = f"{COLORS[item.severity]}{severity}{RESET}"
        lines.extend(
            [
                f"{severity:<18} {item.rule_id} {item.path}:{item.line}:{item.column}",
                f"  {item.title}: {item.message}",
                f"  Evidence: {item.evidence}",
                f"  Fix: {item.remediation}",
            ]
        )
    return "\n".join(lines)


def json_report(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), ensure_ascii=False, indent=2) + "\n"


def markdown_report(result: ScanResult) -> str:
    counts = result.counts
    lines = [
        "# AgentProof scan report",
        "",
        f"**Target:** `{result.target}`  ",
        f"**Overall score:** {result.score}/100 ({_grade(result.score)})  ",
        f"**Security score:** {result.security_score}/100  ",
        f"**Engineering quality:** {result.quality_score}/100  ",
        f"**Files scanned:** {result.files_scanned}  ",
        "",
        "| Critical | High | Medium | Low |",
        "|---:|---:|---:|---:|",
        f"| {counts['critical']} | {counts['high']} | {counts['medium']} | {counts['low']} |",
        "",
    ]
    if result.findings:
        lines.extend(
            [
                "## Findings",
                "",
                "| Severity | Rule | Location | Finding |",
                "|---|---|---|---|",
            ]
        )
        for item in result.findings:
            message = item.message.replace("|", "\\|").replace("\n", " ")
            lines.append(
                f"| {item.severity.label()} | {item.rule_id} | `{item.path}:{item.line}` | {message} |"
            )
        lines.append("")
        for item in result.findings:
            lines.extend(
                [
                    f"### {item.rule_id}: {item.title}",
                    "",
                    f"- **Location:** `{item.path}:{item.line}:{item.column}`",
                    f"- **Evidence:** `{item.evidence.replace('`', chr(39))}`",
                    f"- **Remediation:** {item.remediation}",
                    "",
                ]
            )
    else:
        lines.extend(["## Findings", "", "No findings.", ""])
    lines.extend(
        [
            "---",
            "AgentProof performs static heuristics. A clean report does not prove that a repository is safe.",
            "",
        ]
    )
    return "\n".join(lines)


def sarif_report(result: ScanResult) -> str:
    rules = []
    used = {item.rule_id for item in result.findings}
    for rule_id in sorted(used):
        rule = RULES[rule_id]
        rules.append(
            {
                "id": rule.rule_id,
                "name": rule.title.replace(" ", ""),
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": rule.description},
                "help": {
                    "text": rule.remediation,
                    "markdown": rule.remediation,
                },
                "properties": {
                    "security-severity": {
                        Severity.CRITICAL: "9.5",
                        Severity.HIGH: "8.0",
                        Severity.MEDIUM: "5.5",
                        Severity.LOW: "2.0",
                        Severity.INFO: "0.0",
                    }[rule.severity],
                    "tags": ["security", "agentproof", rule.category],
                },
            }
        )

    def sarif_level(item: Finding) -> str:
        if item.severity >= Severity.HIGH:
            return "error"
        if item.severity == Severity.MEDIUM:
            return "warning"
        return "note"

    results: list[dict[str, Any]] = []
    for item in result.findings:
        location: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {"uri": item.path},
                "region": {
                    "startLine": item.line,
                    "startColumn": item.column,
                },
            }
        }
        results.append(
            {
                "ruleId": item.rule_id,
                "level": sarif_level(item),
                "message": {"text": f"{item.message} Remediation: {item.remediation}"},
                "locations": [location],
                "partialFingerprints": {"primaryLocationLineHash": f"{item.rule_id}:{item.path}:{item.line}"},
            }
        )

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AgentProof",
                        "informationUri": "https://github.com/xie176320/agentproof",
                        "semanticVersion": result.version,
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "score": result.score,
                    "securityScore": result.security_score,
                    "qualityScore": result.quality_score,
                },
            }
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def html_report(result: ScanResult) -> str:
    counts = result.counts
    finding_cards = []
    for item in result.findings:
        finding_cards.append(f"""
        <article class="finding {escape(item.severity.label())}">
          <div class="finding-head"><span>{escape(item.severity.label().upper())}</span>
          <strong>{escape(item.rule_id)} · {escape(item.title)}</strong></div>
          <p>{escape(item.message)}</p>
          <code>{escape(item.path)}:{item.line}:{item.column}</code>
          <p class="evidence">Evidence: {escape(item.evidence)}</p>
          <p><b>Fix:</b> {escape(item.remediation)}</p>
        </article>""")
    body = "\n".join(finding_cards) or "<p class='empty'>No findings.</p>"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AgentProof report</title><style>
:root{{--bg:#07111f;--card:#101d2d;--text:#e8f0fb;--muted:#9fb0c5;--green:#32d583;--red:#ff5d5d;--orange:#fdb022;--blue:#53b1fd}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:16px/1.55 Inter,ui-sans-serif,system-ui;padding:32px}}
main{{max-width:1040px;margin:auto}}header{{padding:32px;border:1px solid #27415d;border-radius:20px;background:linear-gradient(135deg,#0e2238,#123c45)}}
h1{{margin:0 0 8px;font-size:36px}}.muted{{color:var(--muted)}}.metrics{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:22px 0}}
.metric,.finding{{background:var(--card);border:1px solid #24364b;border-radius:14px;padding:18px}}.metric b{{display:block;font-size:28px}}
.finding{{margin:12px 0;border-left:5px solid var(--blue)}}.finding.high,.finding.critical{{border-left-color:var(--red)}}.finding.medium{{border-left-color:var(--orange)}}
.finding-head{{display:flex;gap:12px;align-items:center}}.finding-head span{{font-size:12px;font-weight:800;letter-spacing:.08em}}code{{color:#b9dcff}}
.evidence{{color:var(--muted)}}.empty{{padding:30px;background:var(--card);border-radius:14px}}footer{{color:var(--muted);margin-top:28px;font-size:13px}}
@media(max-width:700px){{.metrics{{grid-template-columns:1fr 1fr}}body{{padding:16px}}}}
</style></head><body><main>
<header><h1>AgentProof</h1><div class="muted">Static AI agent, MCP &amp; Skills security report</div><p>{escape(result.target)}</p></header>
<section class="metrics"><div class="metric"><span>Overall</span><b>{result.score}</b></div><div class="metric"><span>Security</span><b>{result.security_score}</b></div><div class="metric"><span>Quality</span><b>{result.quality_score}</b></div><div class="metric"><span>High/Critical</span><b>{counts["high"] + counts["critical"]}</b></div></section>
<section>{body}</section><footer>Generated by AgentProof {escape(result.version)}. Static analysis cannot prove a repository is risk-free.</footer>
</main></body></html>"""


def render_report(result: ScanResult, report_format: str, *, color: bool = True) -> str:
    renderers = {
        "table": lambda value: terminal_report(value, color=color),
        "json": json_report,
        "markdown": markdown_report,
        "sarif": sarif_report,
        "html": html_report,
    }
    try:
        renderer = renderers[report_format]
    except KeyError as exc:
        raise ValueError(f"Unsupported report format: {report_format}") from exc
    return renderer(result)
