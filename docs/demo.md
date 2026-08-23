# Public demo deployment

The demo in `web/app.py` is designed for Streamlit Community Cloud or the included container.

Live deployment: <https://agentproof.streamlit.app/>

## Streamlit Community Cloud

1. Fork or publish the repository on GitHub.
2. Create a Streamlit app from the repository's `main` branch.
3. Set the entry point to `web/app.py`.
4. Optionally add `AGENTPROOF_GITHUB_TOKEN` as a secret to raise GitHub API limits. Use a fine-grained, read-only token and never expose it to client code.
5. Confirm the page states “Upload disabled” and that no `st.file_uploader` exists.

## Container

```bash
docker build -t agentproof .
docker run --read-only --tmpfs /tmp:rw,noexec,nosuid,size=256m -p 8501:8501 agentproof
```

The read-only container still needs a bounded writable temporary filesystem for public repository archives.

## Verification checklist

- A valid public GitHub repository returns findings and all four downloads.
- Private, nested, HTTP and non-GitHub URLs are rejected.
- A missing repository returns a user-safe error.
- No upload control appears.
- Browser developer tools show that repository text is processed server-side.
- Temporary content is deleted after each uncached scan context exits.
