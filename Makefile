# SPDX-License-Identifier: MIT
PYTHON ?= python3
RUFF ?= ruff

all:

check:
	@if [ -d tests ]; then $(PYTHON) -B -m unittest discover -s tests -v; else echo "no tests yet"; fi

lint:
	$(RUFF) check .

.PHONY: all check lint
