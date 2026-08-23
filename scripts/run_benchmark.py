#!/usr/bin/env python3
"""Run AgentProof against the versioned labeled benchmark corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from agentproof import __version__
from agentproof.rules import RULES
from agentproof.scanner import ScanOptions, scan

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CASES = ROOT / "benchmarks" / "cases.json"


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 1.0


def _materialize(case: dict[str, Any], root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for relative, content in case.get("files", {}).items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    link = case.get("symlink")
    if link:
        path = root / link["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.symlink(link["target"], path)
        except (NotImplementedError, OSError) as exc:
            raise RuntimeError(
                f"Benchmark case {case['id']} requires symbolic-link support: {exc}"
            ) from exc


def run_benchmark(cases_path: Path) -> dict[str, Any]:
    raw = cases_path.read_bytes()
    dataset = json.loads(raw)
    rules = sorted(RULES)
    case_results: list[dict[str, Any]] = []
    totals = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    per_rule = {rule: {"tp": 0, "fp": 0, "fn": 0, "tn": 0} for rule in rules}

    with tempfile.TemporaryDirectory(prefix="agentproof-benchmark-") as temp:
        temp_root = Path(temp)
        for case in dataset["cases"]:
            case_root = temp_root / case["id"]
            _materialize(case, case_root)
            result = scan(
                case_root,
                ScanOptions(
                    project_quality=bool(case.get("project_quality", False)),
                    honor_project_config=False,
                ),
            )
            expected = set(case["expected_rules"])
            actual = {finding.rule_id for finding in result.findings}
            for rule in rules:
                if rule in expected and rule in actual:
                    bucket = "tp"
                elif rule not in expected and rule in actual:
                    bucket = "fp"
                elif rule in expected and rule not in actual:
                    bucket = "fn"
                else:
                    bucket = "tn"
                totals[bucket] += 1
                per_rule[rule][bucket] += 1
            case_results.append(
                {
                    "id": case["id"],
                    "polarity": case["polarity"],
                    "expected_rules": sorted(expected),
                    "detected_rules": sorted(actual),
                    "exact_match": expected == actual,
                }
            )

    precision = _ratio(totals["tp"], totals["tp"] + totals["fp"])
    recall = _ratio(totals["tp"], totals["tp"] + totals["fn"])
    f1 = _ratio(2 * precision * recall, precision + recall)
    false_positive_rate = _ratio(totals["fp"], totals["fp"] + totals["tn"])
    exact_matches = sum(case["exact_match"] for case in case_results)

    rule_metrics: dict[str, Any] = {}
    for rule, counts in per_rule.items():
        rule_precision = _ratio(counts["tp"], counts["tp"] + counts["fp"])
        rule_recall = _ratio(counts["tp"], counts["tp"] + counts["fn"])
        rule_metrics[rule] = {
            **counts,
            "support": counts["tp"] + counts["fn"],
            "precision": rule_precision,
            "recall": rule_recall,
            "f1": _ratio(2 * rule_precision * rule_recall, rule_precision + rule_recall),
        }

    return {
        "schema_version": "1.0",
        "dataset": {
            "name": dataset["name"],
            "version": dataset["dataset_version"],
            "sha256": hashlib.sha256(raw).hexdigest(),
            "cases": len(case_results),
            "positive_cases": sum(case["polarity"] == "positive" for case in case_results),
            "negative_cases": sum(case["polarity"] == "negative" for case in case_results),
            "rules_covered": len({rule for case in case_results for rule in case["expected_rules"]}),
            "rules_total": len(rules),
        },
        "agentproof_version": __version__,
        "metrics": {
            **totals,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "false_positive_rate": false_positive_rate,
            "decision_accuracy": _ratio(totals["tp"] + totals["tn"], sum(totals.values())),
            "exact_case_accuracy": _ratio(exact_matches, len(case_results)),
            "exact_matches": exact_matches,
        },
        "per_rule": rule_metrics,
        "cases": case_results,
        "limitations": [
            "Synthetic cases are authored from the public rule specifications and are not an independent validation set.",
            "Metrics are rule-label classification metrics, not individual finding-instance metrics.",
            "Real-world repositories may contain obfuscation, unsupported formats, context and runtime behavior outside this corpus.",
        ],
    }


def markdown_report(report: dict[str, Any]) -> str:
    dataset = report["dataset"]
    metrics = report["metrics"]
    pct = lambda value: f"{value * 100:.1f}%"
    lines = [
        "# AgentProof benchmark report",
        "",
        f"**Dataset:** {dataset['name']} v{dataset['version']}  ",
        f"**AgentProof:** {report['agentproof_version']}  ",
        f"**Corpus SHA-256:** `{dataset['sha256']}`  ",
        "",
        "## Summary",
        "",
        "| Cases | Positive | Negative | Rules covered | Precision | Recall | F1 | Exact-case accuracy | False-positive rate |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        (
            f"| {dataset['cases']} | {dataset['positive_cases']} | {dataset['negative_cases']} | "
            f"{dataset['rules_covered']}/{dataset['rules_total']} | {pct(metrics['precision'])} | "
            f"{pct(metrics['recall'])} | {pct(metrics['f1'])} | "
            f"{pct(metrics['exact_case_accuracy'])} | {pct(metrics['false_positive_rate'])} |"
        ),
        "",
        "## Per-rule results",
        "",
        "| Rule | Support | TP | FP | FN | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for rule, item in report["per_rule"].items():
        lines.append(
            f"| {rule} | {item['support']} | {item['tp']} | {item['fp']} | {item['fn']} | "
            f"{pct(item['precision'])} | {pct(item['recall'])} | {pct(item['f1'])} |"
        )
    lines.extend(
        [
            "",
            "## Case results",
            "",
            "| Case | Label | Expected | Detected | Result |",
            "|---|---|---|---|---|",
        ]
    )
    for case in report["cases"]:
        expected = ", ".join(case["expected_rules"]) or "none"
        detected = ", ".join(case["detected_rules"]) or "none"
        status = "PASS" if case["exact_match"] else "FAIL"
        lines.append(f"| `{case['id']}` | {case['polarity']} | {expected} | {detected} | {status} |")
    lines.extend(["", "## Interpretation boundary", ""])
    lines.extend(f"- {item}" for item in report["limitations"])
    lines.append("")
    return "\n".join(lines)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--markdown-out", type=Path)
    parser.add_argument("--min-precision", type=float, default=0.0)
    parser.add_argument("--min-recall", type=float, default=0.0)
    parser.add_argument("--min-exact", type=float, default=0.0)
    return parser


def main() -> int:
    args = _parser().parse_args()
    report = run_benchmark(args.cases)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if args.markdown_out:
        args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_out.write_text(markdown_report(report), encoding="utf-8")

    metrics = report["metrics"]
    print(
        "AgentProof benchmark: "
        f"{report['dataset']['cases']} cases, "
        f"precision={metrics['precision']:.3f}, recall={metrics['recall']:.3f}, "
        f"F1={metrics['f1']:.3f}, exact={metrics['exact_case_accuracy']:.3f}"
    )
    return int(
        metrics["precision"] < args.min_precision
        or metrics["recall"] < args.min_recall
        or metrics["exact_case_accuracy"] < args.min_exact
    )


if __name__ == "__main__":
    raise SystemExit(main())
