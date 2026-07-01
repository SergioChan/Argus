.PHONY: check docs schemas bindings rust-bindings lint

check: docs schemas bindings rust-bindings lint

docs:
	python3 scripts/validate_docs.py

schemas:
	python3 scripts/validate_schemas.py

bindings:
	python3 scripts/generate_bindings.py --check

rust-bindings:
	cargo check --manifest-path bindings/rust/Cargo.toml

lint:
	python3 -m py_compile scripts/check.py scripts/generate_bindings.py scripts/validate_docs.py scripts/validate_schemas.py
