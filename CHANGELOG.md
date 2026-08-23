# Changelog

## Unreleased

- Publish the Python distribution as `agentproof-scanner` while preserving the `agentproof` import and CLI.
- Add a 32-case, 16-rule synthetic conformance benchmark with precision, recall, F1 and exact-case accuracy reports.
- Add a Trusted Publishing workflow for secretless PyPI releases with attestations.
- Group Dependabot updates monthly to keep the pull-request queue readable.

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and semantic versioning.

## [Unreleased]

## [0.1.0] - 2026-08-23

### Added

- Dependency-free CLI for local directories and strict public GitHub repository URLs.
- Sixteen deterministic Agent, MCP, Skills, filesystem and engineering-quality rules.
- Evidence redaction for credential findings.
- Terminal, JSON, Markdown, standalone HTML and SARIF reports.
- Composite GitHub Action and CI workflow.
- Public Streamlit demo with repository URL input and file upload disabled.
- Bounded GitHub archive retrieval with traversal and symbolic-link defenses.
- Safe and deliberately vulnerable fixtures with 34 automated tests.

[Unreleased]: https://github.com/xie176320/agentproof/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/xie176320/agentproof/releases/tag/v0.1.0
