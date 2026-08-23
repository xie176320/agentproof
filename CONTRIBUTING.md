# Contributing

Thank you for improving AgentProof. Small, evidence-backed changes are easiest to review.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
python -m unittest discover -s tests -v
agentproof scan . --fail-on high
```

## Proposing a rule

A rule pull request should include:

1. A stable `APxxx` identifier and metadata in `rules.py`.
2. A narrow threat statement, severity rationale and actionable remediation.
3. One malicious fixture and at least one close safe example.
4. Deterministic tests for line number, evidence and redaction where applicable.
5. Documentation in `docs/rules.md`.

Rules must not execute, import, install, compile or render target content. Avoid broad keywords without path or structure constraints.

## Pull requests

- Keep changes focused and explain user-visible behavior.
- Add or update tests and changelog entries.
- Run the standard-library test suite and the self-scan.
- Do not commit real secrets, private repositories, generated environments or large archives.
- Agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
