# AgentProof v0.1.0 — first public alpha

AgentProof v0.1.0 provides a reproducible static security baseline for repositories containing AI Agent instructions, MCP configuration or Agent Skills.

## Highlights

- Scan a local directory or strict public GitHub repository URL without executing target code.
- Detect 16 security and engineering-readiness patterns with file, line, evidence and remediation.
- Export terminal, JSON, Markdown, standalone HTML and SARIF reports.
- Run as a zero-runtime-dependency CLI, composite GitHub Action or URL-only Streamlit application.
- Keep remote analysis bounded to 25 MB archives, 100 MB uncompressed content, 5,000 files and 1 MB text files.
- Reject traversal paths, duplicate archive paths, symbolic links and non-GitHub redirect hosts.
- Ignore target-owned `.agentproof.toml` during remote scans so untrusted repositories cannot disable checks.

## Verification

- 34 automated tests pass on the release source.
- Ruff static checks and formatting checks pass.
- AgentProof scans its own release source at 100/100 with no built-in findings.
- A built wheel installs and runs in a clean virtual environment.
- The Streamlit health endpoint and no-interaction application render were verified locally.

## Important limitation

This is an alpha static-analysis tool. It can miss runtime, obfuscated or semantic risks, and a clean result is not proof that an Agent, MCP server or Skill is safe. Review evidence before acting on findings.
