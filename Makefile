# PromptStrike developer tasks.
# Assumes a virtualenv is active (or adjust PY/PIP below).

PY ?= python
PIP ?= pip

.PHONY: help install test lint scan-demo report-demo clean

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'

install:  ## Install the package with dev extras (editable)
	$(PIP) install -e ".[dev]"

test:  ## Run the unit test suite
	$(PY) -m pytest -q

lint:  ## Lint and format-check the tree
	ruff check .
	ruff format --check .

scan-demo:  ## End-to-end scan of the bundled vulnerable target (needs local Ollama)
	@echo "Requires a local Ollama with: ollama pull dolphin-mistral llama3.2"
	promptstrike scan --config config.yaml --out-dir .demo

report-demo:  ## Re-render a report from the most recent demo results JSON
	promptstrike report "$$(ls -t .demo/promptstrike-results-*.json | head -1)" \
		--report .demo/report.html

clean:  ## Remove build artifacts and demo output
	rm -rf build dist .demo *.egg-info src/*.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
