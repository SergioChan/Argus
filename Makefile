PYTHON ?= python3
PYTHONPATH := src:.

.PHONY: check docs roadmap-audit schemas schema-compat bindings typescript-install typescript-bindings rust-bindings rust-test test lint

check: docs roadmap-audit schemas schema-compat bindings typescript-install typescript-bindings rust-bindings rust-test test lint

docs:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) scripts/validate_docs.py

roadmap-audit:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) scripts/roadmap_audit.py

schemas:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) scripts/validate_schemas.py

schema-compat:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) scripts/schema_compatibility.py --check-manifest

bindings:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) scripts/generate_bindings.py --check

typescript-install:
	npm ci --prefix bindings/typescript

typescript-bindings:
	npm test --prefix bindings/typescript

rust-bindings:
	cargo check --manifest-path bindings/rust/Cargo.toml

rust-test:
	cargo test --manifest-path bindings/rust/Cargo.toml

test:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m unittest discover -s tests

lint:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m py_compile scripts/apply_s3_migrations.py scripts/apply_s8_migrations.py scripts/argus_s2.py scripts/check.py scripts/generate_bindings.py scripts/run_s1_perf_scale_battery.py scripts/run_s2_perf_latency_battery.py scripts/run_s8_read_query_scale_battery.py scripts/run_s8_lineage_scale_battery.py scripts/run_m0_spine_battery.py scripts/roadmap_audit.py scripts/schema_compatibility.py scripts/validate_docs.py scripts/validate_schemas.py src/argus_core/s3.py src/argus_core/s10.py src/argus_runtime/s1_subagent_cli.py src/argus_runtime/s2_cli.py src/argus_runtime/s3_profile_registry.py src/argus_runtime/s3_report_signer_service.py src/argus_runtime/s3_verifier_service.py src/argus_runtime/s3_verify_orchestrator.py src/argusverify/__init__.py tests/test_s3_blind_data_manager.py tests/test_s3_check_plugin_host.py tests/test_s3_cross_code_check_plugin.py tests/test_s3_frozen_pipeline_runner.py tests/test_s3_independence_resolver.py tests/test_s3_injection_check_plugin.py tests/test_s3_leakage_check_plugin.py tests/test_s3_null_control_check_plugin.py tests/test_s3_physical_consistency_check_plugin.py tests/test_s3_profile_registry.py tests/test_s3_profile_resolver.py tests/test_s3_report_canonicalizer.py tests/test_s3_report_signer.py tests/test_s3_statistics_library.py tests/test_s3_trust_store_key_management.py
