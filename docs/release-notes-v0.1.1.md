# AgentProof v0.1.1 — GitHub-native distribution and benchmark evidence

AgentProof v0.1.1 makes the public project directly installable and verifiable through GitHub without a PyPI publishing account.

## Install

```bash
python -m pip install "git+https://github.com/xie176320/agentproof.git@v0.1.1"
```

For an isolated CLI installation:

```bash
pipx install "git+https://github.com/xie176320/agentproof.git@v0.1.1"
```

## Highlights

- Publish a wheel, source archive and `SHA256SUMS` automatically with the GitHub Release.
- Remove the PyPI publishing workflow and all package-token requirements.
- Add a transparent 32-case synthetic conformance benchmark covering AP001–AP016.
- Report precision, recall, F1, exact-case accuracy and per-rule results in JSON and Markdown.
- Group Dependabot updates monthly to keep the pull-request queue readable.
- Update GitHub Actions and Python dependency floors.

## Verification

- 36 automated tests pass on the release source.
- Python 3.11, 3.12 and 3.13 CI jobs pass.
- The package builds as `agentproof_scanner-0.1.1-py3-none-any.whl` and the installed CLI reports `AgentProof 0.1.1`.
- The synthetic conformance benchmark passes all 32 labeled cases with precision, recall, F1 and exact-case accuracy of 100%.
- CodeQL and the AgentProof self-scan pass.

## Interpretation boundary

The benchmark is a transparent synthetic conformance suite, not an independent estimate of real-world detection accuracy. AgentProof remains a static-analysis aid and does not prove that a repository is safe.
