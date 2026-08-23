"""Data models shared by the scanner, CLI, and reporters."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Finding severity ordered from informational to critical."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity | None:
        normalized = value.strip().upper()
        if normalized == "NONE":
            return None
        try:
            return cls[normalized]
        except KeyError as exc:
            choices = ", ".join(item.name.lower() for item in cls)
            raise ValueError(f"Unknown severity '{value}'. Choose: {choices}, none") from exc

    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True, slots=True)
class RuleMetadata:
    """Stable metadata for one AgentProof rule."""

    rule_id: str
    title: str
    severity: Severity
    category: str
    description: str
    remediation: str
    references: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.label()
        data["references"] = list(self.references)
        return data


@dataclass(frozen=True, slots=True)
class Finding:
    """One evidence-backed issue found in a repository."""

    rule_id: str
    title: str
    severity: Severity
    category: str
    path: str
    line: int
    column: int
    message: str
    evidence: str
    remediation: str
    references: tuple[str, ...] = ()

    def fingerprint(self) -> tuple[str, str, int, str]:
        return (self.rule_id, self.path, self.line, self.evidence)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.label()
        data["references"] = list(self.references)
        return data


@dataclass(slots=True)
class ScanResult:
    """Complete immutable-in-practice output of one scan."""

    target: str
    resolved_target: str
    score: int
    security_score: int
    quality_score: int
    files_scanned: int
    files_skipped: int
    duration_ms: int
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    version: str = "0.1.1"

    @property
    def counts(self) -> dict[str, int]:
        counts = {item.label(): 0 for item in Severity}
        for finding in self.findings:
            counts[finding.severity.label()] += 1
        return counts

    @property
    def passed(self) -> bool:
        return not any(item.severity >= Severity.HIGH for item in self.findings)

    def should_fail(self, threshold: Severity | None) -> bool:
        if threshold is None:
            return False
        return any(item.severity >= threshold for item in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "agentproof_version": self.version,
            "target": self.target,
            "resolved_target": self.resolved_target,
            "score": self.score,
            "security_score": self.security_score,
            "quality_score": self.quality_score,
            "passed": self.passed,
            "counts": self.counts,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "duration_ms": self.duration_ms,
            "metadata": self.metadata,
            "findings": [item.to_dict() for item in self.findings],
        }
