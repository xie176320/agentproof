import json
import unittest
from pathlib import Path

from agentproof.reporters import html_report, json_report, markdown_report, sarif_report, terminal_report
from agentproof.scanner import ScanOptions, scan


class ReporterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        target = Path(__file__).parent / "fixtures" / "vulnerable"
        cls.result = scan(target, ScanOptions(project_quality=False, honor_project_config=False))

    def test_json_schema(self) -> None:
        payload = json.loads(json_report(self.result))
        self.assertEqual(payload["schema_version"], "1.0")
        self.assertIn("findings", payload)
        self.assertIn("security_score", payload)

    def test_sarif_schema(self) -> None:
        payload = json.loads(sarif_report(self.result))
        self.assertEqual(payload["version"], "2.1.0")
        self.assertEqual(payload["runs"][0]["tool"]["driver"]["name"], "AgentProof")
        self.assertGreater(len(payload["runs"][0]["results"]), 0)

    def test_markdown_has_findings_table(self) -> None:
        report = markdown_report(self.result)
        self.assertIn("# AgentProof scan report", report)
        self.assertIn("| Severity | Rule |", report)

    def test_html_escapes_target(self) -> None:
        self.result.target = "<script>alert(1)</script>"
        report = html_report(self.result)
        self.assertNotIn("<script>alert", report)
        self.assertIn("&lt;script&gt;", report)

    def test_terminal_no_color(self) -> None:
        report = terminal_report(self.result, color=False)
        self.assertNotIn("\033[", report)
        self.assertIn("AgentProof score", report)


if __name__ == "__main__":
    unittest.main()
