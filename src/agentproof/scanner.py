"""Repository traversal and rule orchestration."""

from __future__ import annotations

import fnmatch
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from .config import ProjectConfig, load_config
from .github import download_public_repository
from .models import Finding, ScanResult, Severity
from .rules import RULES, repository_quality_findings, scan_text


@dataclass(slots=True)
class ScanOptions:
    """User-controlled scan settings with conservative safety limits."""

    excludes: list[str] = field(default_factory=list)
    disabled_rules: set[str] = field(default_factory=set)
    config_path: Path | None = None
    max_file_size: int | None = None
    max_files: int = 10_000
    project_quality: bool = True
    honor_project_config: bool = True


class ScanError(RuntimeError):
    """Raised when a target cannot be scanned."""


def _is_url(target: str) -> bool:
    return target.startswith("https://") or target.startswith("http://")


@contextmanager
def _resolve_target(target: str) -> Iterator[tuple[Path, str, dict[str, object], bool]]:
    if _is_url(target):
        with download_public_repository(target) as (path, metadata):
            yield path, target, metadata, True
        return

    path = Path(target).expanduser().resolve()
    if not path.exists():
        raise ScanError(f"Target does not exist: {target}")
    root = path if path.is_dir() else path.parent
    yield root, str(path), {"source": "local"}, False


def _is_excluded(relative: PurePosixPath, patterns: list[str]) -> bool:
    value = relative.as_posix()
    return any(
        fnmatch.fnmatch(value, pattern)
        or relative.match(pattern)
        or (pattern.endswith("/**") and value == pattern[:-3].rstrip("/"))
        for pattern in patterns
    )


def _is_inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _external_link_finding(path: PurePosixPath) -> Finding:
    rule = RULES["AP016"]
    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        category=rule.category,
        path=path.as_posix(),
        line=1,
        column=1,
        message="Symbolic link resolves outside the repository root.",
        evidence="[external symbolic link]",
        remediation=rule.remediation,
        references=rule.references,
    )


def _decode_text(path: Path, max_bytes: int) -> str | None:
    try:
        with path.open("rb") as handle:
            data = handle.read(max_bytes + 1)
    except (OSError, PermissionError):
        return None
    if len(data) > max_bytes or b"\x00" in data[:8_192]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _scores(findings: list[Finding]) -> tuple[int, int, int]:
    security_penalty = {
        Severity.CRITICAL: 30,
        Severity.HIGH: 14,
        Severity.MEDIUM: 6,
        Severity.LOW: 2,
        Severity.INFO: 0,
    }
    security = max(
        0,
        100 - sum(security_penalty[item.severity] for item in findings if item.category != "project-quality"),
    )
    quality_findings = sum(item.category == "project-quality" for item in findings)
    quality = max(0, 100 - 25 * quality_findings)
    overall = round(security * 0.8 + quality * 0.2)
    return overall, security, quality


def scan(target: str | Path = ".", options: ScanOptions | None = None) -> ScanResult:
    """Statically scan a local directory or public GitHub repository URL."""

    started = time.perf_counter()
    target_text = str(target)
    options = options or ScanOptions()

    with _resolve_target(target_text) as (root, resolved, metadata, remote):
        root = root.resolve()
        config = ProjectConfig()
        if options.honor_project_config and not remote:
            try:
                config = load_config(root, options.config_path)
            except (OSError, ValueError) as exc:
                raise ScanError(str(exc)) from exc

        patterns = [*config.excludes, *options.excludes]
        disabled = config.disabled_rules | {item.upper() for item in options.disabled_rules}
        max_file_size = options.max_file_size or config.max_file_size
        findings: list[Finding] = []
        relative_files: set[str] = set()
        files_scanned = 0
        files_skipped = 0
        files_seen = 0

        requested = Path(resolved) if not remote else root
        candidates = [requested] if not remote and requested.is_file() else root.rglob("*")
        for path in candidates:
            try:
                relative = PurePosixPath(path.relative_to(root).as_posix())
            except ValueError:
                files_skipped += 1
                continue
            if _is_excluded(relative, patterns):
                continue
            if path.is_symlink():
                if not _is_inside(path, root):
                    findings.append(_external_link_finding(relative))
                files_skipped += 1
                continue
            if not path.is_file():
                continue
            relative_files.add(relative.as_posix())
            files_seen += 1
            if files_seen > options.max_files:
                raise ScanError(f"Target exceeds the {options.max_files}-file safety limit")
            text = _decode_text(path, max_file_size)
            if text is None:
                files_skipped += 1
                continue
            files_scanned += 1
            findings.extend(scan_text(relative, text))

        if options.project_quality and (remote or requested.is_dir()):
            findings.extend(repository_quality_findings(root, relative_files))

        unique = {item.fingerprint(): item for item in findings}
        filtered = [item for item in unique.values() if item.rule_id not in disabled]
        filtered.sort(key=lambda item: (-int(item.severity), item.path, item.line, item.rule_id))
        score, security_score, quality_score = _scores(filtered)
        elapsed = round((time.perf_counter() - started) * 1000)

        return ScanResult(
            target=target_text,
            resolved_target=resolved,
            score=score,
            security_score=security_score,
            quality_score=quality_score,
            files_scanned=files_scanned,
            files_skipped=files_skipped,
            duration_ms=elapsed,
            findings=filtered,
            metadata=metadata,
        )
