.PHONY: check docs schemas lint

check: docs schemas lint

docs:
	python3 scripts/validate_docs.py

schemas:
	python3 scripts/validate_schemas.py

lint:
	python3 -m py_compile scripts/check.py scripts/validate_docs.py scripts/validate_schemas.py
