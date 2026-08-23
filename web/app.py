"""Public Streamlit demo for AgentProof.

The demo intentionally accepts public GitHub repository URLs only. It has no file
uploader and never executes repository code.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentproof.github import GitHubFetchError  # noqa: E402
from agentproof.reporters import html_report, markdown_report, sarif_report  # noqa: E402
from agentproof.rules import all_rules  # noqa: E402
from agentproof.scanner import ScanError, ScanOptions, scan  # noqa: E402

st.set_page_config(
    page_title="AgentProof · AI Agent Security Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
<style>
    .stApp { background: #07111f; color: #e8f0fb; }
    [data-testid="stSidebar"] { background: #0d1a29; }
    .hero { padding: 2.2rem; border: 1px solid #27415d; border-radius: 22px;
      background: linear-gradient(135deg,#0d233a 0%,#123d45 100%); margin-bottom: 1.2rem; }
    .hero h1 { margin: 0; font-size: clamp(2.2rem,5vw,4.2rem); letter-spacing: -.05em; }
    .hero p { color: #b7c9dc; max-width: 800px; font-size: 1.08rem; }
    .eyebrow { color: #61e7b7; text-transform: uppercase; letter-spacing: .13em; font-weight: 800; font-size: .75rem; }
    .boundary { border-left: 4px solid #32d583; background: #0c2a2a; padding: .9rem 1rem; border-radius: 8px; }
    [data-testid="stMetric"] { border: 1px solid #27415d; background: #101d2d; border-radius: 14px; padding: 1rem; }
    .severity-critical,.severity-high { color: #ff7070; font-weight: 800; }
    .severity-medium { color: #fdb022; font-weight: 800; }
    .severity-low { color: #53b1fd; font-weight: 800; }
</style>
""",
    unsafe_allow_html=True,
)


@st.cache_data(ttl=300, show_spinner=False)
def scan_cached(url: str):
    return scan(
        url,
        ScanOptions(
            honor_project_config=False,
            max_files=5_000,
            max_file_size=1_000_000,
        ),
    )


with st.sidebar:
    st.subheader("Public demo boundary")
    st.success("✓ Public GitHub URLs only\n\n✓ Upload disabled\n\n✓ Static analysis only")
    st.caption(
        "AgentProof downloads a bounded public archive, reads text, and deletes the temporary copy after the scan."
    )
    st.divider()
    st.subheader("Built-in coverage")
    for rule in all_rules():
        st.caption(f"**{rule.rule_id}** · {rule.title}")
    st.divider()
    st.caption("Heuristic findings require review. A clean scan is not proof of safety.")

st.markdown(
    """
<section class="hero">
  <div class="eyebrow">Open-source · deterministic · evidence-backed</div>
  <h1>AgentProof</h1>
  <p>Find unsafe instructions, over-broad MCP permissions, exposed secrets and engineering gaps
  before an AI agent repository reaches users.</p>
</section>
""",
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="boundary"><b>No repository code is executed.</b> The public demo accepts a plain GitHub repository URL and does not provide file upload.</div>',
    unsafe_allow_html=True,
)

url = st.text_input(
    "Public GitHub repository",
    placeholder="https://github.com/owner/repository",
    help="Private repositories, nested file links, and non-GitHub hosts are rejected.",
)
left, right = st.columns([1, 4])
with left:
    run = st.button("Scan repository", type="primary", use_container_width=True)
with right:
    st.caption("Safety limits: 25 MB archive · 100 MB extracted · 5,000 files · 1 MB per text file")

if run:
    if not url.strip():
        st.warning("Enter a public GitHub repository URL.")
    else:
        try:
            with st.spinner("Retrieving and scanning public repository text…"):
                result = scan_cached(url.strip())
        except (GitHubFetchError, ScanError, OSError, ValueError) as exc:
            st.error(str(exc))
        else:
            st.session_state["result"] = result

result = st.session_state.get("result")
if result:
    counts = result.counts
    st.subheader("Repository scorecard")
    columns = st.columns(5)
    columns[0].metric("Overall", f"{result.score}/100")
    columns[1].metric("Security", f"{result.security_score}/100")
    columns[2].metric("Engineering", f"{result.quality_score}/100")
    columns[3].metric("Critical / high", counts["critical"] + counts["high"])
    columns[4].metric("Files scanned", result.files_scanned)

    findings_tab, architecture_tab, export_tab = st.tabs(["Findings", "How it works", "Export"])
    with findings_tab:
        if not result.findings:
            st.success("No built-in rule produced a finding. Manual review is still required.")
        for finding in result.findings:
            label = f"{finding.severity.label().upper()} · {finding.rule_id} · {finding.title}"
            with st.expander(label, expanded=finding.severity.value >= 3):
                st.code(f"{finding.path}:{finding.line}:{finding.column}", language=None)
                st.write(finding.message)
                st.caption(f"Evidence: {finding.evidence}")
                st.markdown(f"**Recommended fix:** {finding.remediation}")
                for reference in finding.references:
                    st.markdown(f"[Reference]({reference})")
    with architecture_tab:
        st.markdown(
            """
1. Strictly validate a `github.com/owner/repository` URL.
2. Retrieve public metadata and a bounded archive.
3. Reject traversal paths and symbolic links before extraction.
4. Decode text only; never import, build, or execute repository content.
5. Run deterministic rules and attach line-level evidence.
6. Delete the temporary repository when the request completes.
"""
        )
    with export_tab:
        st.write(
            "Download the same result in formats designed for people, automation, or GitHub code scanning."
        )
        c1, c2, c3, c4 = st.columns(4)
        c1.download_button(
            "Markdown",
            markdown_report(result),
            "agentproof-report.md",
            "text/markdown",
            use_container_width=True,
        )
        c2.download_button(
            "JSON",
            json.dumps(result.to_dict(), indent=2),
            "agentproof-report.json",
            "application/json",
            use_container_width=True,
        )
        c3.download_button(
            "SARIF",
            sarif_report(result),
            "agentproof-report.sarif",
            "application/sarif+json",
            use_container_width=True,
        )
        c4.download_button(
            "HTML", html_report(result), "agentproof-report.html", "text/html", use_container_width=True
        )
else:
    st.subheader("What AgentProof checks")
    a, b, c = st.columns(3)
    a.markdown(
        "**Agent instructions**\n\nBoundary overrides, unrestricted autonomy, destructive commands and dynamic execution."
    )
    b.markdown(
        "**MCP & Skills**\n\nShell-backed servers, wildcard approvals, unsafe transport, mutable packages and incomplete metadata."
    )
    c.markdown("**Repository quality**\n\nSecurity policy, CI, tests and open-source license readiness.")
