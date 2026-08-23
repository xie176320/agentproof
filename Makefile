.PHONY: install test scan demo report benchmark build

install:
	python -m pip install -e .

test:
	PYTHONPATH=src python -m unittest discover -s tests -v

scan:
	PYTHONPATH=src python -m agentproof scan . --fail-on high --no-color

demo:
	PYTHONPATH=src streamlit run web/app.py

report:
	PYTHONPATH=src python -m agentproof scan examples/vulnerable-agent --no-quality --format html --output reports/demo.html --fail-on none

benchmark:
	PYTHONPATH=src python scripts/run_benchmark.py --json-out benchmarks/results/v0.1.1.json --markdown-out benchmarks/results/v0.1.1.md

build:
	python -m build
