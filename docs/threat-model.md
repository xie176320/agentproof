# Threat model

## Assets

- The operator's filesystem, credentials, network identity and CI runner.
- Source text and configuration in local or remotely fetched repositories.
- Integrity of AgentProof findings and exported reports.

## Untrusted inputs

- Every byte inside the target repository.
- Repository names and URLs supplied to the web demo or CLI.
- Archive paths, compression ratios, file counts, encodings and symbolic links.
- Natural-language instructions designed to influence an AI consumer.

## Security objectives

- Never execute or import target repository code.
- Never send target content to an LLM or third-party analysis API.
- Keep remote requests on approved GitHub API endpoints constructed from validated owner/repository names.
- Bound download size, uncompressed size, file count and per-file text size.
- Prevent path traversal and external symbolic-link reads.
- Redact credential evidence in reports.
- Keep report rendering escaped and free of active target HTML.

## Non-goals

- Runtime sandboxing or malware detonation.
- Complete secret scanning, dependency vulnerability analysis or license compliance.
- Proving that an Agent, MCP server or Skill is safe.
- Inspecting private repositories in the public web demo.

## Known residual risks

- ZIP bombs that remain below configured limits can consume time or memory.
- Regex and structural rules can produce false positives or false negatives.
- A public GitHub archive can change between metadata retrieval and download.
- Terminal consumers should treat evidence as untrusted text even though AgentProof normalizes it.

Please report bypasses privately according to [SECURITY.md](../SECURITY.md).
