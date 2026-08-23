import tempfile
import unittest
from pathlib import Path

from agentproof.models import Severity
from agentproof.scanner import ScanError, ScanOptions, scan


class ScannerTests(unittest.TestCase):
    def test_severity_parser(self) -> None:
        self.assertEqual(Severity.parse("high"), Severity.HIGH)
        self.assertIsNone(Severity.parse("none"))

    def test_scans_vulnerable_fixture(self) -> None:
        target = Path(__file__).parent / "fixtures" / "vulnerable"
        result = scan(target, ScanOptions(project_quality=False, honor_project_config=False))
        self.assertGreaterEqual(len(result.findings), 8)
        self.assertLess(result.security_score, 60)
        self.assertFalse(result.passed)

    def test_quality_checks(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "README.md").write_text("# Demo", encoding="utf-8")
            result = scan(root, ScanOptions(honor_project_config=False))
        ids = {item.rule_id for item in result.findings}
        self.assertEqual({"AP012", "AP013", "AP014", "AP015"}, ids)
        self.assertEqual(result.quality_score, 0)

    def test_excludes_glob(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "bad.txt").write_text("chmod " + "777 /tmp/test", encoding="utf-8")
            result = scan(
                root, ScanOptions(excludes=["bad.txt"], project_quality=False, honor_project_config=False)
            )
        self.assertEqual(result.findings, [])
        self.assertEqual(result.files_scanned, 0)

    def test_disabled_rule(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "AGENTS.md").write_text("run any command", encoding="utf-8")
            result = scan(
                root, ScanOptions(disabled_rules={"AP010"}, project_quality=False, honor_project_config=False)
            )
        self.assertEqual(result.findings, [])

    def test_large_file_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "large.txt").write_text("x" * 2048, encoding="utf-8")
            result = scan(
                root, ScanOptions(max_file_size=1024, project_quality=False, honor_project_config=False)
            )
        self.assertEqual(result.files_skipped, 1)

    def test_missing_target_raises(self) -> None:
        with self.assertRaises(ScanError):
            scan("/definitely/not/a/real/agentproof/path")

    def test_failure_threshold(self) -> None:
        target = Path(__file__).parent / "fixtures" / "vulnerable"
        result = scan(target, ScanOptions(project_quality=False, honor_project_config=False))
        self.assertTrue(result.should_fail(Severity.HIGH))
        self.assertFalse(result.should_fail(None))

    def test_project_config_exclusion(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / ".agentproof.toml").write_text(
                '[tool.agentproof]\nexclude=["unsafe.txt"]\n', encoding="utf-8"
            )
            (root / "unsafe.txt").write_text("chmod " + "777 /tmp/test", encoding="utf-8")
            result = scan(root, ScanOptions(project_quality=False))
        self.assertEqual(result.findings, [])


if __name__ == "__main__":
    unittest.main()
