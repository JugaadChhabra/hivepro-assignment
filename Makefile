.PHONY: install lint test test-integration test-all run eval

install:
	pip install -e ".[dev]"

lint:
	ruff check .
	mypy

test:  # fast gate — no network, no model download
	pytest -m "not network"

test-integration:  # real NIST catalog + embeddings (needs network)
	pytest -m network

test-all:
	pytest

run:
	uvicorn riskagent.app:app --host 0.0.0.0 --port 7860

eval:
	python eval.py

eval-retrieval:
	python eval.py --retrieval

dump:
	python eval.py --dump scored_findings.csv
