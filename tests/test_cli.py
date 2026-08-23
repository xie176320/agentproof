import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from agentproof.cli import main


class CliTests(unittest.TestCase):
    def test_vulnerable_exit_code(self) -> None:
        target = Path(__file__).parent / "fixtures" / "vulnerable"
        with redirect_stdout(io.StringIO()):
            code = main(["scan", str(target), "--no-quality", "--format", "json"])
        self.assertEqual(code, 1)

    def test_none_threshold_succeeds(self) -> None:
        target = Path(__file__).parent / "fixtures" / "vulnerable"
        with redirect_stdout(io.StringIO()):
            code = main(["scan", str(target), "--no-quality", "--fail-on", "none", "--format", "json"])
        self.assertEqual(code, 0)

    def test_writes_report(self) -> None:
        target = Path(__file__).parent / "fixtures" / "safe"
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "report.sarif"
            with redirect_stdout(io.StringIO()):
                code = main(["scan", str(target), "--no-quality", "--format", "sarif", "-o", str(output)])
            self.assertEqual(code, 0)
            self.assertTrue(output.read_text(encoding="utf-8").startswith("{"))


if __name__ == "__main__":
    unittest.main()
