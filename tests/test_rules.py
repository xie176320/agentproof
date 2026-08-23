import unittest
from pathlib import Path, PurePosixPath

from agentproof.rules import is_agent_instruction, is_mcp_config, scan_text

FIXTURES = Path(__file__).parent / "fixtures"


class RuleTests(unittest.TestCase):
    def test_agent_instruction_paths(self) -> None:
        self.assertTrue(is_agent_instruction(PurePosixPath("AGENTS.md")))
        self.assertTrue(is_agent_instruction(PurePosixPath("skills/review/SKILL.md")))
        self.assertFalse(is_agent_instruction(PurePosixPath("README.md")))

    def test_mcp_paths(self) -> None:
        self.assertTrue(is_mcp_config(PurePosixPath(".mcp.json")))
        self.assertTrue(is_mcp_config(PurePosixPath("config/tools.mcp.json")))
        self.assertFalse(is_mcp_config(PurePosixPath("package.json")))

    def test_vulnerable_mcp_rules(self) -> None:
        path = FIXTURES / "vulnerable" / ".mcp.json"
        findings = scan_text(PurePosixPath(".mcp.json"), path.read_text())
        ids = {item.rule_id for item in findings}
        self.assertTrue({"AP001", "AP002", "AP005", "AP006", "AP007", "AP008"}.issubset(ids))

    def test_vulnerable_agent_rules(self) -> None:
        path = FIXTURES / "vulnerable" / "AGENTS.md"
        findings = scan_text(PurePosixPath("AGENTS.md"), path.read_text())
        ids = {item.rule_id for item in findings}
        self.assertEqual(ids, {"AP003", "AP004", "AP010"})

    def test_missing_skill_frontmatter(self) -> None:
        path = FIXTURES / "vulnerable" / "SKILL.md"
        findings = scan_text(PurePosixPath("SKILL.md"), path.read_text())
        self.assertIn("AP009", {item.rule_id for item in findings})

    def test_safe_files_have_no_findings(self) -> None:
        root = FIXTURES / "safe"
        for path in root.iterdir():
            findings = scan_text(PurePosixPath(path.name), path.read_text())
            self.assertEqual(findings, [], path.name)

    def test_placeholder_secret_is_ignored(self) -> None:
        text = 'api_key = "${MY_API_KEY}"\npassword = "example-password"'
        findings = scan_text(PurePosixPath("config.toml"), text)
        self.assertNotIn("AP001", {item.rule_id for item in findings})

    def test_secret_evidence_is_redacted(self) -> None:
        text = "access_" + 'token = "' + "abcdefghijklmnopqrstuvwx" + '"'
        findings = scan_text(PurePosixPath("config.toml"), text)
        secret = next(item for item in findings if item.rule_id == "AP001")
        self.assertIn("REDACTED", secret.evidence)
        self.assertNotIn("abcdefghijklmnopqrstuvwx", secret.evidence)

    def test_line_number_is_reported(self) -> None:
        text = "safe\nsafe\nchmod " + "777 /tmp/tool\n"
        finding = next(item for item in scan_text(PurePosixPath("setup.sh"), text) if item.rule_id == "AP003")
        self.assertEqual(finding.line, 3)

    def test_negated_agent_phrase_is_not_flagged(self) -> None:
        text = "Do not ignore previous instructions. Never run any command without review."
        findings = scan_text(PurePosixPath("AGENTS.md"), text)
        self.assertNotIn("AP004", {item.rule_id for item in findings})
        self.assertNotIn("AP010", {item.rule_id for item in findings})

    def test_scoped_pinned_package_is_safe(self) -> None:
        text = '{"mcpServers":{"safe":{"command":"npx","args":["@scope/server@1.2.3"]}}}'
        findings = scan_text(PurePosixPath(".mcp.json"), text)
        self.assertNotIn("AP008", {item.rule_id for item in findings})

    def test_nested_wildcard_is_flagged(self) -> None:
        text = '{"mcpServers":{"unsafe":{"command":"node","alwaysAllow":["*"]}}}'
        findings = scan_text(PurePosixPath(".mcp.json"), text)
        self.assertIn("AP006", {item.rule_id for item in findings})


if __name__ == "__main__":
    unittest.main()
