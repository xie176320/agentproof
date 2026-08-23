## What changed

<!-- Describe the user-visible change and why it is needed. -->

## Security boundary

- [ ] The change does not execute, import, install, compile, or render target repository code.
- [ ] Remote input remains restricted to validated public GitHub repository URLs.
- [ ] Findings redact credential evidence and reports escape untrusted content.

## Verification

- [ ] Added or updated malicious and safe fixtures.
- [ ] `python -m unittest discover -s tests -v` passes.
- [ ] `agentproof scan . --fail-on high` passes.
- [ ] Documentation and changelog are updated when needed.
