# SPDX-License-Identifier: MIT
PREFIX ?= /usr
DESTDIR ?=
PYTHON ?= python3
RUFF ?= ruff
SHARE = $(DESTDIR)$(PREFIX)/share/aurora-xart

all:

check:
	$(PYTHON) -B -m unittest discover -s tests

lint:
	$(RUFF) check .

install:
	install -d $(SHARE)/aurora_xart $(DESTDIR)$(PREFIX)/bin
	install -d $(DESTDIR)$(PREFIX)/share/man/man8 $(DESTDIR)$(PREFIX)/share/doc/aurora-xart
	install -m644 aurora_xart/*.py $(SHARE)/aurora_xart/
	install -m755 bin/aurora-xart $(DESTDIR)$(PREFIX)/bin/aurora-xart
	install -m644 docs/aurora-xart.8 $(DESTDIR)$(PREFIX)/share/man/man8/aurora-xart.8
	install -m644 README.md docs/FORMATS.md $(DESTDIR)$(PREFIX)/share/doc/aurora-xart/

.PHONY: all check lint install
