import json
import unittest
from pathlib import Path

from agentproof.rules import RULES

CASES = Path(__file__).parents[1] / "benchmarks" / "cases.json"


class BenchmarkManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.payload = json.loads(CASES.read_text(encoding="utf-8"))

    def test_case_ids_are_unique_and_labels_are_valid(self) -> None:
        cases = self.payload["cases"]
        ids = [case["id"] for case in cases]
        self.assertEqual(len(ids), len(set(ids)))
        for case in cases:
            self.assertTrue(set(case["expected_rules"]).issubset(RULES))

    def test_every_rule_has_positive_and_close_negative_coverage(self) -> None:
        cases = self.payload["cases"]
        positive = {rule for case in cases for rule in case["expected_rules"]}
        negative_targets = {
            case["id"].split("-", 1)[0].upper()
            for case in cases
            if case["polarity"] == "negative" and case["id"].startswith("ap")
        }
        self.assertEqual(positive, set(RULES))
        self.assertEqual(negative_targets, set(RULES))


if __name__ == "__main__":
    unittest.main()
