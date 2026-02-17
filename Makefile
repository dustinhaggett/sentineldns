PYTHON ?= python3

.PHONY: setup data dataset train serve simulate test format

setup:
	$(PYTHON) -m pip install -e ".[dev]"

data:
	$(PYTHON) -m sentineldns.cli.main download-data

dataset:
	$(PYTHON) -m sentineldns.cli.main build-dataset

train:
	$(PYTHON) -m sentineldns.cli.main train-domain-risk
	$(PYTHON) -m sentineldns.cli.main train-anomaly

serve:
	$(PYTHON) -m sentineldns.service.run --host 127.0.0.1 --port 8787

simulate:
	$(PYTHON) -m sentineldns.cli.main simulate

test:
	$(PYTHON) -m pytest -q

format:
	$(PYTHON) -m black src tests
	$(PYTHON) -m ruff check src tests --fix
