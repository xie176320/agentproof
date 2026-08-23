.PHONY: install test scan demo report build

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

build:
	python -m build
