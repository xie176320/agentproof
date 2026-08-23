# AgentProof benchmark

The benchmark is a transparent synthetic conformance suite for the deterministic AP001–AP016 rules. It contains one labeled positive and one close-negative case per rule, including repository-quality checks and symbolic-link boundary behavior.

Run it locally:

```bash
PYTHONPATH=src python scripts/run_benchmark.py \
  --json-out benchmarks/results/v0.1.0.json \
  --markdown-out benchmarks/results/v0.1.0.md
```

## Metrics

- **Precision:** detected expected rule labels divided by all detected rule labels.
- **Recall:** detected expected rule labels divided by all expected rule labels.
- **F1:** harmonic mean of precision and recall.
- **Exact-case accuracy:** cases whose complete detected rule set exactly matches the label set.
- **False-positive rate:** false-positive rule decisions divided by all expected-negative rule decisions.

Each case is evaluated against every built-in rule. The corpus is intentionally small, deterministic and reviewable. It proves rule conformance on these fixtures; it does not estimate performance on the population of real-world repositories. Real-world and independently labeled corpora are planned for later versions.

Unsafe strings in `cases.json` are synthetic and are excluded from the repository self-scan. No real credentials or private data are included.
