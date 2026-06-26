# MemForensicAI — Makefile

.PHONY: help setup run interactive test lint typecheck report clean

help:
	@echo ""
	@echo "  MemForensicAI — Available Commands"
	@echo "  ──────────────────────────────────────────────"
	@echo "  make setup        Install dependencies + create .env"
	@echo "  make run          Analyze a memory dump (set DUMP= env var)"
	@echo "  make interactive  Start interactive forensics REPL"
	@echo "  make test         Run all unit tests"
	@echo "  make lint         Run ruff linter"
	@echo "  make typecheck    Run mypy type checker"
	@echo "  make report       Generate report from saved session"
	@echo "  make clean        Remove output files"
	@echo ""

setup:
	pip install -r requirements.txt
	pip install -e .
	@if not exist .env (copy .env.example .env && echo "Created .env — please fill in your API key and Volatility path.")

run:
	python -m cli.main analyze --dump "$(DUMP)" --output ./output

interactive:
	python -m cli.main interactive

mock:
	python -m cli.main interactive --mock

test:
	pytest tests/ -v --tb=short --cov=. --cov-report=term-missing

lint:
	ruff check .

typecheck:
	mypy core/ tools/ cli/ reporting/ --ignore-missing-imports

report:
	python -m cli.main report --session "$(SESSION)"

clean:
	rm -rf output/*.pdf output/*.html output/*.json
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -name "*.pyc" -delete
