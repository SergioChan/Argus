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
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m py_compile scripts/apply_s3_migrations.py scripts/apply_s8_migrations.py scripts/argus_s2.py scripts/check.py scripts/generate_bindings.py scripts/generate_s10_gvisor_monitor_config.py scripts/gvisor_security_probe.py scripts/run_s1_perf_scale_battery.py scripts/run_s2_perf_latency_battery.py scripts/run_s8_read_query_scale_battery.py scripts/run_s8_lineage_scale_battery.py scripts/run_m0_spine_battery.py scripts/run_m1_external_referee_battery.py scripts/run_m1_pilot_console_battery.py scripts/run_m1_s2_reference_builder_battery.py scripts/run_s10_gvisor_battery.py scripts/run_s10_security_monitor_battery.py scripts/run_s10_firecracker_battery.py scripts/run_s10_egress_battery.py scripts/s10_cosign_fixture.py scripts/roadmap_audit.py scripts/schema_compatibility.py scripts/validate_docs.py scripts/validate_schemas.py src/argus_core/s3.py src/argus_core/s10.py src/argus_egress/__init__.py src/argus_runtime/http_json.py src/argus_runtime/m1_reference_runtime.py src/argus_runtime/m1_pilot_console.py src/argus_runtime/m1_reference_service_auth.py src/argus_runtime/s1_reference_demo_service.py src/argus_runtime/s1_subagent_cli.py src/argus_runtime/s2_cli.py src/argus_runtime/s2_reference_builder_service.py src/argus_runtime/s2_isolated_training_entrypoint.py src/argus_runtime/s3_profile_registry.py src/argus_runtime/s3_reference_referee_service.py src/argus_runtime/s3_report_signer_service.py src/argus_runtime/s3_verifier_service.py src/argus_runtime/s3_verify_orchestrator.py src/argus_runtime/s7_reference_adapter_service.py src/argus_runtime/s8_persistence.py src/argus_runtime/s10_audit_persistence.py src/argus_runtime/s10_egress_proxy_service.py src/argus_runtime/s10_reference_security_pager_service.py src/argus_runtime/s10_security_monitor_client.py src/argus_runtime/s10_supervisor_service.py src/argus_runtime/s11_reference_observatory_service.py src/argusverify/__init__.py tests/test_m1_reference_lifecycle_services.py tests/test_m1_pilot_console.py tests/test_s3_blind_data_manager.py tests/test_s3_calibration_check_plugin.py tests/test_s3_claim_tiering_rule_engine.py tests/test_s3_check_plugin_host.py tests/test_s3_cross_code_check_plugin.py tests/test_s3_frozen_pipeline_runner.py tests/test_s3_independence_resolver.py tests/test_s3_injection_check_plugin.py tests/test_s3_leakage_check_plugin.py tests/test_s3_null_control_check_plugin.py tests/test_s3_physical_consistency_check_plugin.py tests/test_s3_profile_registry.py tests/test_s3_profile_resolver.py tests/test_s3_reference_referee_service.py tests/test_s3_report_builder.py tests/test_s3_report_canonicalizer.py tests/test_s3_report_signer.py tests/test_s3_statistics_library.py tests/test_s3_trust_store_key_management.py tests/test_s10_audit_ledger.py tests/test_s10_egress_proxy.py tests/test_s10_forensic_quarantine.py tests/test_s10_gvisor_runtime.py tests/test_s10_firecracker_runtime.py tests/test_s10_image_verification.py tests/test_s10_reference_security_pager.py tests/test_s10_security_monitor.py
	sh -n deploy/argus-m0/security/firecracker-guest-init.sh deploy/argus-m0/security/firecracker-federated-probe.sh
