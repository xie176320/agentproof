# Security policy

## Supported versions

AgentProof is currently pre-1.0. Security fixes are applied to the latest release on the `main` branch.

## Report a vulnerability

Do not open a public issue for a vulnerability. Use [GitHub private vulnerability reporting](https://github.com/xie176320/agentproof/security/advisories/new) and include:

- affected version or commit;
- minimal reproduction;
- expected and observed security boundary;
- impact on local scans, remote scans, reports or the web demo;
- suggested mitigation, if available.

Never include live credentials or private repository content. You should receive an acknowledgement within seven days. No bounty is promised.

## Scope priorities

- execution of target repository content;
- archive traversal or reading outside the scan root;
- SSRF or bypass of the strict public-GitHub URL boundary;
- secret evidence not being redacted;
- active HTML or script injection into reports;
- meaningful denial of service below documented size limits.
