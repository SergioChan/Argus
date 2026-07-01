.PHONY: check docs lint

check: docs lint

docs:
	python3 scripts/validate_docs.py

lint:
	python3 -m py_compile scripts/check.py scripts/validate_docs.py
