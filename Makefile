.PHONY: check docs roadmap-audit schemas schema-compat bindings typescript-install typescript-bindings rust-bindings rust-test test lint

check: docs roadmap-audit schemas schema-compat bindings typescript-install typescript-bindings rust-bindings rust-test test lint

docs:
	python3 scripts/validate_docs.py

roadmap-audit:
	python3 scripts/roadmap_audit.py

schemas:
	python3 scripts/validate_schemas.py

schema-compat:
	python3 scripts/schema_compatibility.py --check-manifest

bindings:
	python3 scripts/generate_bindings.py --check

typescript-install:
	npm ci --prefix bindings/typescript

typescript-bindings:
	npm test --prefix bindings/typescript

rust-bindings:
	cargo check --manifest-path bindings/rust/Cargo.toml

rust-test:
	cargo test --manifest-path bindings/rust/Cargo.toml

test:
	python3 -m unittest discover -s tests

lint:
	python3 -m py_compile scripts/apply_s8_migrations.py scripts/check.py scripts/generate_bindings.py scripts/run_s8_lineage_scale_battery.py scripts/run_m0_spine_battery.py scripts/roadmap_audit.py scripts/schema_compatibility.py scripts/validate_docs.py scripts/validate_schemas.py
