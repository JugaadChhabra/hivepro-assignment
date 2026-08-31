.PHONY: install lint test run eval

install:
	pip install -e ".[dev]"

lint:
	ruff check .
	mypy

test:
	pytest

run:
	@echo "make run: not implemented until phase 5 (app.py)" && exit 1

eval:
	@echo "make eval: not implemented until phase 6 (eval.py)" && exit 1
