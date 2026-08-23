"""Generate deterministic demo reports from the intentionally vulnerable fixture."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentproof.reporters import html_report, json_report, markdown_report, sarif_report  # noqa: E402
from agentproof.scanner import ScanOptions, scan  # noqa: E402


def main() -> None:
    result = scan(
        ROOT / "examples" / "vulnerable-agent",
        ScanOptions(project_quality=False, honor_project_config=False),
    )
    output = ROOT / "reports"
    output.mkdir(exist_ok=True)
    reports = {
        "demo.html": html_report(result),
        "demo.json": json_report(result),
        "demo.md": markdown_report(result),
        "demo.sarif": sarif_report(result),
    }
    for name, content in reports.items():
        (output / name).write_text(content, encoding="utf-8")
        print(f"wrote reports/{name}")


if __name__ == "__main__":
    main()
