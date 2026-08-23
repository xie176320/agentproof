# Rule reference

AgentProof rules are deterministic and versioned. A rule must produce a file location, bounded evidence and actionable remediation.

## Security rules

### AP001 — Hardcoded secret · critical

Detects selected credential formats and literal values assigned to credential-like keys. Common placeholders and environment-variable references are ignored. Evidence is redacted before it reaches any reporter.

### AP002 — Remote script piped to a shell · high

Detects `curl` or `wget` output passed directly to a shell. Prefer a pinned release artifact with a verified checksum or signature.

### AP003 — Destructive or over-permissive command · high

Detects a compact set of destructive root/home filesystem operations, disk formatting, database deletion and mode `777`. The rule deliberately avoids flagging every use of `rm`.

### AP004 — Instruction-boundary override · high

Runs only on recognized Agent instruction and Skill paths. Detects requests to ignore higher-priority instructions, expose hidden prompts or bypass safety policy.

### AP005 — Shell-backed MCP server · high

Parses MCP JSON and flags server commands that launch through `sh`, `bash`, `cmd`, PowerShell and similar general-purpose shells.

### AP006 — Wildcard MCP approval · high

Flags wildcard entries in common automatic-approval keys. Review the client's exact authorization semantics and use explicit tool names.

### AP007 — Insecure transport · medium

Detects remote plaintext HTTP endpoints and common TLS-verification bypasses. Localhost HTTP is permitted because local transports frequently terminate without TLS.

### AP008 — Unpinned package execution · medium

Detects selected package runners whose package version can float. Pin an exact version and preserve integrity metadata.

### AP009 — Incomplete Skill metadata · low

Checks `SKILL.md` for closed YAML frontmatter containing `name` and `description` keys. It does not attempt to fully validate a vendor-specific Skill schema.

### AP010 — Unrestricted Agent autonomy · high

Runs only on Agent instruction and Skill files. Flags explicit unlimited command/filesystem authority or confirmation bypasses.

### AP011 — Dynamic code execution · high

Detects a small set of external-input-to-`eval`/`exec` and decoded-content-to-shell patterns.

### AP016 — External symbolic link · medium

Local scans skip links that resolve outside the scan root. Remote archives containing any symbolic link are rejected before extraction.

## Engineering-quality rules

AP012–AP015 check for a security policy, GitHub Actions workflow, open-source license and automated tests. They are low-severity readiness findings and can be disabled with `--no-quality`.

## False positives

Security documentation and malicious fixtures can intentionally contain unsafe patterns. Prefer excluding a narrow fixture path in `.agentproof.toml` instead of disabling a rule globally. Future releases will add inline suppressions that require a written rationale.
