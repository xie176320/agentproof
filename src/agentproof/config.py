"""Configuration loading with safe, dependency-free defaults."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_EXCLUDES = (
    ".git/**",
    ".venv/**",
    "venv/**",
    "node_modules/**",
    "dist/**",
    "build/**",
    "__pycache__/**",
    ".pytest_cache/**",
    ".ruff_cache/**",
    "*.min.js",
    "*.map",
)


@dataclass(slots=True)
class ProjectConfig:
    """Project-level scanner configuration."""

    excludes: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    disabled_rules: set[str] = field(default_factory=set)
    max_file_size: int = 1_000_000


def load_config(root: Path, explicit_path: Path | None = None) -> ProjectConfig:
    """Load ``.agentproof.toml`` from a target root when present."""

    path = explicit_path or root / ".agentproof.toml"
    config = ProjectConfig()
    if not path.is_file():
        return config

    with path.open("rb") as handle:
        raw = tomllib.load(handle)
    section = raw.get("tool", {}).get("agentproof", raw.get("agentproof", {}))
    if not isinstance(section, dict):
        raise ValueError(f"Invalid AgentProof configuration in {path}")

    excludes = section.get("exclude", [])
    if excludes:
        if not isinstance(excludes, list) or not all(isinstance(item, str) for item in excludes):
            raise ValueError("agentproof.exclude must be a list of strings")
        config.excludes.extend(excludes)

    disabled = section.get("disable_rules", [])
    if disabled:
        if not isinstance(disabled, list) or not all(isinstance(item, str) for item in disabled):
            raise ValueError("agentproof.disable_rules must be a list of rule IDs")
        config.disabled_rules = {item.upper() for item in disabled}

    max_file_size = section.get("max_file_size")
    if max_file_size is not None:
        if not isinstance(max_file_size, int) or max_file_size < 1_024:
            raise ValueError("agentproof.max_file_size must be an integer >= 1024")
        config.max_file_size = max_file_size
    return config
