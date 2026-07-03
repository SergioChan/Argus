#!/usr/bin/env python3
"""Run the M0 Spine Integration Slice battery against the argus-m0 compose stack."""

from __future__ import annotations

import argparse
from contextlib import closing
from dataclasses import asdict, replace
from decimal import Decimal
from hashlib import sha256
import hmac
from io import BytesIO
import json
import math
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import threading
import time
from typing import Any
from urllib import error, parse, request
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from argus_core import (
    ArtifactRecord,
    BudgetCaps,
    InMemoryPolicyBundleTrustStore,
    InMemoryPolicyService,
    InMemoryTokenService,
    LaunchEnvelope,
    LaunchRequest,
    Lineage,
    PolicyBundle,
    PolicyBundleSignatureError,
    PolicyBundleSigner,
    Producer,
    ResourceCeilings,
    ScopeGrant,
    SIGNATURE_VERIFICATION_ACCEPTED,
    hash_json,
    s8_checkpoint_signature_payload,
)
from argusverify import C3ReportSigner, InMemoryVerifierTrustStore, verify_report


DEFAULT_IMAGE = "busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
M0_C3_VERIFIER_KEY_ID = "argus-m0-c3-verifier"
HALT_LATENCY_TRIALS = 50
HALT_LATENCY_LIMIT_S = 2.0
TOKEN_REVOCATION_PROPAGATION_SLO_S = 2.0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose-file", default=str(ROOT / "deploy/argus-m0/compose.yaml"))
    parser.add_argument("--image", default=os.environ.get("ARGUS_S10_TEST_IMAGE", DEFAULT_IMAGE))
    parser.add_argument("--evidence-file")
    parser.add_argument("--keep-stack", action="store_true")
    parser.add_argument("--skip-compose-up", action="store_true")
    args = parser.parse_args()

    docker = shutil.which("docker")
    if docker is None:
        raise RuntimeError("docker CLI is required for the M0 spine battery")

    evidence: dict[str, Any] = {
        "battery": "M0 Spine Integration Slice",
        "commit": _git_head(),
        "working_tree_dirty": _git_dirty(),
        "results": [],
    }
    runtime_secrets = _m0_runtime_secrets()
    price_table_now = int(time.time())
    ports = {
        "ARGUS_M0_POSTGRES_PORT": str(_free_port()),
        "ARGUS_M0_MINIO_PORT": str(_free_port()),
        "ARGUS_M0_MINIO_CONSOLE_PORT": str(_free_port()),
        "ARGUS_M0_S8_PORT": str(_free_port()),
        "ARGUS_M0_S10_PORT": str(_free_port()),
    }
    env = {
        **os.environ,
        **ports,
        "ARGUS_RUNTIME_BOOTSTRAP_TOKEN": runtime_secrets["bootstrap_token"],
        "ARGUS_RUNTIME_IDENTITY_SIGNING_KEY": runtime_secrets["identity_signing_key"],
        "ARGUS_RUNTIME_IDENTITY_MINT_POLICY_JSON": _m0_identity_mint_policy_json(),
        "ARGUS_M0_HEALTH_TOKEN": runtime_secrets["health_token"],
        "ARGUS_S10_TOKEN_ED25519_PRIVATE_KEY_HEX": runtime_secrets["s10_token_ed25519_private_key_hex"],
        "ARGUS_S10_TOKEN_ED25519_PUBLIC_KEY_HEX": runtime_secrets["s10_token_ed25519_public_key_hex"],
        "ARGUS_S10_POLICY_SIGNING_KEY": runtime_secrets["s10_policy_signing_key"],
        "ARGUS_S10_CHECKPOINT_SIGNING_KEY": runtime_secrets["s10_checkpoint_signing_key"],
        "ARGUS_S10_CHECKPOINT_SIGNER_AUTH_TOKEN": runtime_secrets["s10_checkpoint_signer_auth_token"],
        "ARGUS_S10_VERIFIER_KEY_AUTH_TOKEN": runtime_secrets["s10_verifier_key_auth_token"],
        "ARGUS_S10_C3_VERIFIER_KEYS_JSON": json.dumps(
            {M0_C3_VERIFIER_KEY_ID: runtime_secrets["c3_verifier_signing_key"]},
            separators=(",", ":"),
            sort_keys=True,
        ),
        "ARGUS_S10_PRICE_TABLE_SIGNING_KEY": runtime_secrets["s10_price_table_signing_key"],
        "ARGUS_S10_PRICE_TABLE_ISSUED_AT": str(price_table_now - 60),
        "ARGUS_S10_PRICE_TABLE_EXPIRES_AT": str(price_table_now + 86_400),
        "ARGUS_S8_BROKER_WRITE_KEY": runtime_secrets["s8_broker_write_key"],
    }
    s8_url = f"http://127.0.0.1:{ports['ARGUS_M0_S8_PORT']}"
    s10_url = f"http://127.0.0.1:{ports['ARGUS_M0_S10_PORT']}"
    evidence["target"] = {
        "compose_file": str(Path(args.compose_file).resolve()),
        "s8_url": s8_url,
        "s10_url": s10_url,
        "ports": ports,
        "persistence": "postgres-minio",
        "auth_callers": list(_m0_identity_requests().keys()),
    }

    try:
        if not args.skip_compose_up:
            _record(evidence, "deploy", "argus-m0 compose up --build --wait")
            _run([docker, "compose", "-f", args.compose_file, "up", "-d", "--build", "--wait"], env=env, timeout=240)
        _wait_health(f"{s8_url}/healthz", token=runtime_secrets["health_token"])
        _wait_health(f"{s10_url}/healthz", token=runtime_secrets["health_token"])
        _battery_runtime_identity_mint_policy(evidence, s10_url, bootstrap_token=runtime_secrets["bootstrap_token"])
        auth_tokens = _mint_m0_runtime_identities(s10_url=s10_url, bootstrap_token=runtime_secrets["bootstrap_token"])
        _ensure_image(docker, args.image)

        _battery_a_contracts(evidence)
        _battery_s8_capability_scopes(
            evidence,
            s8_url,
            read_token=auth_tokens["read"],
            write_token=auth_tokens["write"],
        )
        s10_checkpoint_signer_from_health = _battery_runtime_auth_required(
            evidence,
            s8_url,
            s10_url,
            bootstrap_token=runtime_secrets["bootstrap_token"],
            health_token=runtime_secrets["health_token"],
        )
        write_scope_json = _mint_store_scope(s10_url=s10_url, token=auth_tokens["write"])
        _battery_direct_s8_write_denied(evidence, s8_url, token=auth_tokens["read"])
        _battery_forged_scope_token_denied(evidence, s10_url, write_scope_json, token=auth_tokens["write"])
        _battery_revoked_scope_token_denied(evidence, s10_url, token=auth_tokens["write"])
        _battery_revoked_budget_token_denied(
            evidence,
            s10_url,
            image=args.image,
            token=auth_tokens["spine"],
        )
        _battery_revoked_inflight_sandbox_halted(
            evidence,
            s10_url,
            s8_url=s8_url,
            image=args.image,
            token=auth_tokens["spine"],
            read_token=auth_tokens["read"],
        )
        _battery_b_incomplete_lineage(evidence, s10_url, write_scope_json, token=auth_tokens["write"])
        _battery_c_write_once(evidence, s10_url, write_scope_json, token=auth_tokens["write"])
        dataset_scope_json = _mint_store_scope(s10_url=s10_url, token=auth_tokens["dataset"])
        _battery_dataset_registry_service(
            evidence,
            s10_url=s10_url,
            s8_url=s8_url,
            dataset_scope_json=dataset_scope_json,
            dataset_token=auth_tokens["dataset"],
            read_token=auth_tokens["read"],
            verifier_label_token=auth_tokens["verifier-label"],
            write_token=auth_tokens["write"],
        )
        verifier_scope_json = _mint_store_scope(s10_url=s10_url, token=auth_tokens["verify"])
        _battery_deployed_report_verifier(
            evidence,
            s10_url,
            verifier_scope_json=verifier_scope_json,
            verifier_token=auth_tokens["verify"],
            model_scope_json=write_scope_json,
            model_token=auth_tokens["write"],
            verifier_signing_key=runtime_secrets["c3_verifier_signing_key"].encode("utf-8"),
            verifier_key_auth_token=runtime_secrets["s10_verifier_key_auth_token"],
        )
        _battery_signed_policy_service(
            evidence,
            policy_signing_key=runtime_secrets["s10_policy_signing_key"].encode("utf-8"),
        )
        _battery_runtime_class_hint_policy(
            evidence,
            signing_key=runtime_secrets["s10_signing_key"].encode("utf-8"),
            policy_signing_key=runtime_secrets["s10_policy_signing_key"].encode("utf-8"),
        )

        budget_json = _post_json(
            f"{s10_url}/v1/budget-tokens",
            {},
            expected_status=201,
            token=auth_tokens["spine"],
        )
        scope_json = _post_json(
            f"{s10_url}/v1/scope-tokens",
            {},
            expected_status=201,
            token=auth_tokens["spine"],
        )
        if not str(budget_json.get("signature", "")).startswith("ed25519:"):
            raise AssertionError(f"S10 budget token was not Ed25519-signed: {budget_json}")
        if not str(scope_json.get("signature", "")).startswith("ed25519:"):
            raise AssertionError(f"S10 scope token was not Ed25519-signed: {scope_json}")
        launch_result = _run_no_network_launch(
            image=args.image,
            budget=budget_json,
            scope=scope_json,
            s10_url=s10_url,
            token=auth_tokens["spine"],
            s8_url=s8_url,
            read_token=auth_tokens["read"],
        )
        spend_final = _battery_spend_final(
            s8_url=s8_url,
            read_token=auth_tokens["read"],
            job_id="m0-spine-job",
            launch_provenance_ref=launch_result["launch_provenance_ref"],
            expected_state="SUCCEEDED",
        )
        model_record = _post_json(
            f"{s10_url}/v1/store/artifacts",
            {
                "scope_token": scope_json,
                "kind": "model",
                "payload": {"weights": [1, 2, 3], "source": "m0-spine"},
                "producer": {"subsystem": "S2", "version": "0.0.0"},
                "lineage": {
                    "input_refs": [launch_result["launch_provenance_ref"]],
                    "code_ref": "git:m0-spine-model",
                    "environment_digest": launch_result["exec_environment_digest"],
                    "seeds": ["seed-1"],
                },
            },
            expected_status=201,
            token=auth_tokens["spine"],
        )
        fetched = _get_json(f"{s8_url}/v1/artifacts/{model_record['artifact_ref']}/record", token=auth_tokens["read"])
        original_payload = _get_json(
            f"{s8_url}/v1/artifacts/{model_record['artifact_ref']}/payload",
            token=auth_tokens["read"],
        )
        lineage = _get_json(
            f"{s8_url}/v1/lineage/{model_record['artifact_ref']}?direction=ancestors",
            token=auth_tokens["read"],
        )
        impact = _get_json(
            f"{s8_url}/v1/impact-set?seed_ref={parse.quote(launch_result['launch_provenance_ref'], safe='')}",
            token=auth_tokens["read"],
        )
        query = _get_json(
            f"{s8_url}/v1/artifacts?kind=model&producer_subsystem=S2&page_size=10",
            token=auth_tokens["read"],
        )
        manifest = _get_json(
            f"{s8_url}/v1/reproducibility-manifest/{parse.quote(model_record['artifact_ref'], safe='')}",
            token=auth_tokens["read"],
        )
        reproducibility_check = _post_json(
            f"{s8_url}/v1/reproducibility-checks",
            {
                "artifact_ref": model_record["artifact_ref"],
                "rerun_payload": {"weights": [1, 2, 3], "source": "m0-spine"},
                "tolerance_id": "m0-spine-hash-equal",
            },
            expected_status=201,
            token=auth_tokens["write"],
        )
        reproducibility_fail = _post_json(
            f"{s8_url}/v1/reproducibility-checks",
            {
                "artifact_ref": model_record["artifact_ref"],
                "rerun_payload": {"weights": [9, 9, 9], "source": "m0-spine"},
                "tolerance_id": "m0-spine-hash-equal-fail",
            },
            expected_status=201,
            token=auth_tokens["write"],
        )
        reproducibility_status = _get_json(
            f"{s8_url}/v1/reproducibility-status/{parse.quote(model_record['artifact_ref'], safe='')}",
            token=auth_tokens["read"],
        )
        refetched = _get_json(f"{s8_url}/v1/artifacts/{model_record['artifact_ref']}/record", token=auth_tokens["read"])
        post_check_payload = _get_json(
            f"{s8_url}/v1/artifacts/{model_record['artifact_ref']}/payload",
            token=auth_tokens["read"],
        )
        audit_slice = _get_json(
            f"{s8_url}/v1/audit-slice?artifact_ref={parse.quote(model_record['artifact_ref'], safe='')}",
            token=auth_tokens["read"],
        )
        audit_page1 = _get_json(
            f"{s8_url}/v1/audit-slice?"
            + parse.urlencode(
                [
                    ("artifact_ref", launch_result["launch_provenance_ref"]),
                    ("artifact_ref", model_record["artifact_ref"]),
                    ("page_size", "1"),
                ]
            ),
            token=auth_tokens["read"],
        )
        audit_write_denial = _get_json(
            f"{s8_url}/v1/audit-slice?artifact_ref={parse.quote(model_record['artifact_ref'], safe='')}",
            expected_status=403,
            token=auth_tokens["write"],
        )
        audit_page2 = _get_json(
            f"{s8_url}/v1/audit-slice?"
            + parse.urlencode(
                [
                    ("artifact_ref", launch_result["launch_provenance_ref"]),
                    ("artifact_ref", model_record["artifact_ref"]),
                    ("page_size", "1"),
                    ("page_token", str(audit_page1["next_page_token"])),
                ]
            ),
            token=auth_tokens["read"],
        )
        ancestor_refs = {node["artifact_ref"] for node in lineage["nodes"]}
        impact_refs = {record["artifact_ref"] for record in impact["records"]}
        query_refs = {record["artifact_ref"] for record in query["records"]}
        if fetched["producer"]["job_id"] != "m0-spine-job":
            raise AssertionError("broker did not seal producer job_id")
        if launch_result["launch_provenance_ref"] not in ancestor_refs:
            raise AssertionError("model lineage did not include launch provenance")
        if model_record["artifact_ref"] not in impact_refs:
            raise AssertionError("model impact set did not include downstream model")
        if model_record["artifact_ref"] not in query_refs:
            raise AssertionError("artifact query did not include broker-written model")
        if manifest["lineage"]["code_ref"] != "git:m0-spine-model":
            raise AssertionError("reproducibility manifest did not preserve model code_ref")
        if launch_result["launch_provenance_ref"] not in manifest["lineage"]["input_refs"]:
            raise AssertionError("reproducibility manifest did not include launch provenance input")
        if manifest["lineage"]["environment_digest"] != launch_result["exec_environment_digest"]:
            raise AssertionError("reproducibility manifest did not preserve environment digest")
        if "seed-1" not in manifest["lineage"]["seeds"]:
            raise AssertionError("reproducibility manifest did not preserve seed material")
        if reproducibility_check["verdict"] != "PASS" or reproducibility_check["comparator_id"] != "hash_equal":
            raise AssertionError("deployed reproducibility check did not record hash_equal PASS")
        if reproducibility_fail["verdict"] != "FAIL" or reproducibility_fail["comparator_id"] != "hash_equal":
            raise AssertionError("deployed reproducibility check did not record hash_equal FAIL")
        if not reproducibility_fail.get("non_promotable") or not reproducibility_fail.get("non_reproducible"):
            raise AssertionError(f"failed deployed reproducibility check was not non-promotable: {reproducibility_fail}")
        if not reproducibility_status.get("non_promotable") or not reproducibility_status.get("non_reproducible"):
            raise AssertionError(f"deployed reproducibility status was not non-promotable: {reproducibility_status}")
        if int(reproducibility_status.get("check_count") or 0) < 2:
            raise AssertionError(f"deployed reproducibility status did not retain PASS and FAIL checks: {reproducibility_status}")
        if int(reproducibility_status.get("failed_check_count") or 0) < 1:
            raise AssertionError(f"deployed reproducibility status did not retain failed check count: {reproducibility_status}")
        if refetched["content_hash"] != fetched["content_hash"]:
            raise AssertionError("failed reproducibility check mutated original artifact record content_hash")
        if refetched["lineage"] != fetched["lineage"]:
            raise AssertionError("failed reproducibility check mutated original artifact lineage")
        if post_check_payload != original_payload:
            raise AssertionError("failed reproducibility check mutated original artifact payload")
        if not audit_slice["verification"]["valid"]:
            raise AssertionError("deployed audit slice did not verify")
        audit_leaf_refs = {leaf["artifact_id"] for leaf in audit_slice["audit_slice"]["leaves"]}
        if model_record["artifact_ref"] not in audit_leaf_refs:
            raise AssertionError("deployed audit slice did not include broker-written model leaf")
        audit_page1_refs = [leaf["artifact_id"] for leaf in audit_page1["audit_slice"]["leaves"]]
        audit_page2_refs = [leaf["artifact_id"] for leaf in audit_page2["audit_slice"]["leaves"]]
        if audit_page1["next_page_token"] != 1:
            raise AssertionError(f"deployed audit slice did not return the first pagination token: {audit_page1}")
        if audit_page2["next_page_token"] is not None:
            raise AssertionError(f"deployed audit slice final page returned an unexpected token: {audit_page2}")
        if audit_page1_refs != [launch_result["launch_provenance_ref"]]:
            raise AssertionError(f"first audit export page did not contain launch provenance: {audit_page1}")
        if audit_page2_refs != [model_record["artifact_ref"]]:
            raise AssertionError(f"second audit export page did not contain broker-written model: {audit_page2}")
        if not audit_page1["verification"]["valid"] or not audit_page2["verification"]["valid"]:
            raise AssertionError(f"deployed paged audit slices did not verify: {audit_page1} {audit_page2}")
        if audit_write_denial.get("error") != "CapabilityDenied":
            raise AssertionError(f"write token was not denied by deployed audit export route: {audit_write_denial}")
        if not audit_slice["audit_slice"]["merkle_checkpoints"][0]["signature"].startswith("hmac-sha256:"):
            raise AssertionError("deployed audit slice did not include signed checkpoint")
        _record(
            evidence,
            "f",
            "real Docker launch had no default route; S10 broker wrote model C4 record; S8 read, query, lineage, impact-set, reproducibility manifest/check, and audit-slice verification passed",
            {
                "sandbox_stdout": launch_result["stdout"],
                "launch_handle_state": launch_result["state"],
                "launch_provenance_ref": launch_result["launch_provenance_ref"],
                "spend_final_ref": spend_final["artifact_ref"],
                "spend_final_price_table_version": spend_final["price_table_version"],
                "spend_final_cost_usd_exact": spend_final["cost_usd_exact"],
                "spend_final_meter_sample_count": spend_final["meter_sample_count"],
                "spend_final_meter_max_cadence_s": spend_final["meter_max_cadence_s"],
                "spend_final_meter_dcgm_available": spend_final["meter_dcgm_available"],
                "spend_final_meter_nvidia_smi_available": spend_final["meter_nvidia_smi_available"],
                "spend_final_meter_gpu_count": spend_final["meter_gpu_count"],
                "spend_final_meter_gpu_models": spend_final["meter_gpu_models"],
                "spend_final_meter_mig_enabled": spend_final["meter_mig_enabled"],
                "spend_final_meter_mig_instance_count": spend_final["meter_mig_instance_count"],
                "spend_final_meter_gpu_telemetry_source": spend_final["meter_gpu_telemetry_source"],
                "model_ref": model_record["artifact_ref"],
                "impact_refs": sorted(impact_refs),
                "query_refs": sorted(query_refs),
                "reproducibility_check_id": reproducibility_check["check_id"],
                "reproducibility_verdict": reproducibility_check["verdict"],
                "reproducibility_fail_check_id": reproducibility_fail["check_id"],
                "reproducibility_fail_verdict": reproducibility_fail["verdict"],
                "reproducibility_non_reproducible": reproducibility_status["non_reproducible"],
                "reproducibility_non_promotable": reproducibility_status["non_promotable"],
                "reproducibility_check_count": reproducibility_status["check_count"],
                "reproducibility_failed_check_count": reproducibility_status["failed_check_count"],
                "reproducibility_original_content_hash": fetched["content_hash"],
                "reproducibility_post_check_content_hash": refetched["content_hash"],
                "reproducibility_original_record_unchanged": refetched == fetched,
                "reproducibility_original_payload_unchanged": post_check_payload == original_payload,
                "audit_leaf_refs": sorted(audit_leaf_refs),
                "audit_multi_page1_refs": audit_page1_refs,
                "audit_multi_page2_refs": audit_page2_refs,
                "audit_multi_page1_next_page_token": audit_page1["next_page_token"],
                "audit_multi_page2_next_page_token": audit_page2["next_page_token"],
                "audit_write_token_error": audit_write_denial["error"],
                "audit_checkpoint_sequence": audit_slice["audit_slice"]["merkle_checkpoints"][0]["sequence"],
            },
        )

        _battery_e_budget_halt(
            evidence,
            s10_url,
            args.image,
            s8_url,
            token=auth_tokens["halt"],
            read_token=auth_tokens["read"],
        )
        _battery_partial_capture(
            evidence,
            s10_url,
            args.image,
            s8_url,
            token=auth_tokens["partial-capture"],
            read_token=auth_tokens["read"],
        )
        _battery_halt_latency_trials(
            evidence,
            s10_url,
            args.image,
            s8_url,
            token=auth_tokens["halt-latency"],
            read_token=auth_tokens["read"],
        )
        _battery_non_injected_meter_gap(
            evidence,
            docker=docker,
            compose_file=args.compose_file,
            compose_env=env,
            s10_url=s10_url,
            s8_url=s8_url,
            image=args.image,
            token=auth_tokens["meter-gap"],
            read_token=auth_tokens["read"],
            health_token=runtime_secrets["health_token"],
        )
        _battery_g_argusverify(evidence)
        _battery_real_persistence(
            evidence,
            ports,
            s8_url=s8_url,
            token=auth_tokens["read"],
            checkpoint_signing_key=runtime_secrets["s10_checkpoint_signing_key"].encode("utf-8"),
            checkpoint_signer_provider_from_health=s10_checkpoint_signer_from_health,
        )
        _battery_d_tamper_detected(
            evidence,
            s8_url=s8_url,
            token=auth_tokens["read"],
            health_token=runtime_secrets["health_token"],
            minio_port=ports["ARGUS_M0_MINIO_PORT"],
            model_record=model_record,
            unrelated_ref=launch_result["launch_provenance_ref"],
        )

        if args.evidence_file:
            Path(args.evidence_file).write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
        print(json.dumps(evidence, indent=2, sort_keys=True))
        return 0
    finally:
        if not args.skip_compose_up and not args.keep_stack:
            _run([docker, "compose", "-f", args.compose_file, "down", "--volumes"], env=env, timeout=120, check=False)


def _battery_a_contracts(evidence: dict[str, Any]) -> None:
    commands = [
        [sys.executable, "scripts/validate_schemas.py"],
        [sys.executable, "scripts/schema_compatibility.py", "--check-manifest"],
        [sys.executable, "scripts/generate_bindings.py", "--check"],
        ["npm", "ci", "--prefix", "bindings/typescript"],
        ["npm", "test", "--prefix", "bindings/typescript"],
        ["cargo", "test", "--manifest-path", "bindings/rust/Cargo.toml"],
    ]
    for command in commands:
        _run(command, timeout=120)
    _record(evidence, "a", "schemas meta-validated and Python/TypeScript/Rust binding gates passed")


def _m0_runtime_secrets() -> dict[str, str]:
    return {
        "bootstrap_token": f"argus-bootstrap-{uuid4().hex}",
        "health_token": f"argus-health-{uuid4().hex}",
        "identity_signing_key": f"argus-identity-key-{uuid4().hex}",
        "s10_signing_key": f"argus-s10-key-{uuid4().hex}",
        "s10_token_ed25519_private_key_hex": "1111111111111111111111111111111111111111111111111111111111111111",
        "s10_token_ed25519_public_key_hex": "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        "s10_policy_signing_key": f"argus-s10-policy-key-{uuid4().hex}",
        "s10_checkpoint_signing_key": f"argus-s10-checkpoint-key-{uuid4().hex}",
        "s10_checkpoint_signer_auth_token": f"argus-s10-checkpoint-signer-{uuid4().hex}",
        "s10_verifier_key_auth_token": f"argus-s10-verifier-key-{uuid4().hex}",
        "s10_price_table_signing_key": f"argus-s10-price-table-key-{uuid4().hex}",
        "s8_broker_write_key": f"argus-s8-broker-key-{uuid4().hex}",
        "c3_verifier_signing_key": f"argus-c3-verifier-key-{uuid4().hex}",
    }


def _m0_identity_requests() -> dict[str, dict[str, Any]]:
    return {
        "read": {
            "caller_id": "m0-read",
            "job_id": "m0-read",
            "root_request_id": "m0-read-root",
            "scopes": {
                "capabilities": ["s8.read"],
            },
        },
        "write": {
            "caller_id": "m0-spine-write",
            "job_id": "m0-spine-write-tests",
            "root_request_id": "m0-spine-write-root",
            "scopes": {
                "broker_audiences": ["store"],
                "capabilities": ["s8.reproducibility.write"],
                "producer_subsystems": ["S2"],
                "sandbox_risk_class": "standard",
            },
        },
        "dataset": {
            "caller_id": "m0-dataset-registry",
            "job_id": "m0-dataset-registry-job",
            "root_request_id": "m0-dataset-registry-root",
            "scopes": {
                "broker_audiences": ["store"],
                "capabilities": ["s8.read", "s8.dataset.write"],
                "producer_subsystems": ["S8"],
                "sandbox_risk_class": "standard",
            },
        },
        "verifier-label": {
            "caller_id": "m0-verifier-label-reader",
            "job_id": "m0-verifier-label-reader-job",
            "root_request_id": "m0-verifier-label-reader-root",
            "scopes": {
                "capabilities": ["s8.read", "s8.verifier-labels.read"],
                "sandbox_risk_class": "standard",
            },
        },
        "spine": {
            "caller_id": "m0-spine-launch",
            "job_id": "m0-spine-job",
            "root_request_id": "m0-spine-root",
            "budget_caps": {"max_compute_units": 10, "max_wallclock_s": 10, "max_cost_usd": 5},
            "scopes": {
                "broker_audiences": ["store"],
                "capabilities": ["s8.read", "s8.reproducibility.write"],
                "producer_subsystems": ["S2"],
                "sandbox_risk_class": "standard",
            },
        },
        "halt": {
            "caller_id": "m0-budget-halt",
            "job_id": "m0-budget-halt-job",
            "root_request_id": "m0-budget-halt-root",
            "budget_caps": {"max_compute_units": 1, "max_wallclock_s": 1, "max_cost_usd": 5},
            "scopes": {"sandbox_risk_class": "standard"},
        },
        "halt-latency": {
            "caller_id": "m0-halt-latency",
            "job_id": "m0-halt-latency-job",
            "root_request_id": "m0-halt-latency-root",
            "budget_caps": {"max_compute_units": 1, "max_wallclock_s": 1, "max_cost_usd": 5},
            "scopes": {"sandbox_risk_class": "standard"},
        },
        "meter-gap": {
            "caller_id": "m0-meter-gap",
            "job_id": "m0-meter-gap-job",
            "root_request_id": "m0-meter-gap-root",
            "budget_caps": {"max_compute_units": 10, "max_wallclock_s": 10, "max_cost_usd": 5},
            "scopes": {"sandbox_risk_class": "standard"},
        },
        "partial-capture": {
            "caller_id": "m0-partial-capture",
            "job_id": "m0-partial-capture-job",
            "root_request_id": "m0-partial-capture-root",
            "budget_caps": {"max_compute_units": 10, "max_wallclock_s": 10, "max_cost_usd": 5},
            "scopes": {"sandbox_risk_class": "standard"},
        },
        "verify": {
            "caller_id": "m0-verifier",
            "job_id": "m0-verifier-job",
            "root_request_id": "m0-verifier-root",
            "scopes": {
                "broker_audiences": ["store"],
                "capabilities": ["s8.read"],
                "producer_subsystems": ["S3"],
                "sandbox_risk_class": "standard",
            },
        },
    }


def _m0_identity_mint_policy_json() -> str:
    policy: dict[str, dict[str, Any]] = {}
    for body in _m0_identity_requests().values():
        caller_id = body["caller_id"]
        policy[caller_id] = {
            "job_id": body["job_id"],
            "root_request_id": body["root_request_id"],
            "scopes": body.get("scopes", {}),
            "budget_caps": body.get("budget_caps", {}),
            "max_ttl_s": 900,
        }
    return json.dumps(policy, separators=(",", ":"), sort_keys=True)


def _battery_runtime_identity_mint_policy(evidence: dict[str, Any], s10_url: str, *, bootstrap_token: str) -> None:
    override = _post_json(
        f"{s10_url}/v1/runtime-identities",
        {"caller_id": "m0-spine-launch", "job_id": "attacker-selected-job"},
        expected_status=403,
        token=bootstrap_token,
    )
    unknown = _post_json(
        f"{s10_url}/v1/runtime-identities",
        {"caller_id": "unknown-launcher"},
        expected_status=403,
        token=bootstrap_token,
    )
    ttl = _post_json(
        f"{s10_url}/v1/runtime-identities",
        {"caller_id": "m0-spine-launch", "ttl_s": 901},
        expected_status=403,
        token=bootstrap_token,
    )
    if override["error"] != "IdentityOverrideError":
        raise AssertionError(f"unexpected runtime identity override error: {override}")
    if unknown["error"] != "PermissionError" or ttl["error"] != "PermissionError":
        raise AssertionError(f"unexpected runtime identity policy errors: unknown={unknown}, ttl={ttl}")
    _record(
        evidence,
        "identity-policy",
        "bootstrap runtime identity mint is constrained by server-side caller policy",
        {
            "override": override["error"],
            "unknown_caller": unknown["error"],
            "ttl_ceiling": ttl["error"],
        },
    )


def _mint_m0_runtime_identities(*, s10_url: str, bootstrap_token: str) -> dict[str, str]:
    minted: dict[str, str] = {}
    for name, body in _m0_identity_requests().items():
        response = _post_json(
            f"{s10_url}/v1/runtime-identities",
            {"caller_id": body["caller_id"], "ttl_s": 900},
            expected_status=201,
            token=bootstrap_token,
        )
        minted[name] = response["access_token"]
    return minted


def _battery_runtime_auth_required(
    evidence: dict[str, Any],
    s8_url: str,
    s10_url: str,
    *,
    bootstrap_token: str,
    health_token: str,
) -> str:
    s8_health_no_auth = _get_json(f"{s8_url}/healthz", expected_status=401)
    s10_scope_no_auth = _post_json(f"{s10_url}/v1/scope-tokens", {}, expected_status=401)
    s8_health_bootstrap = _get_json(f"{s8_url}/healthz", expected_status=401, token=bootstrap_token)
    s10_health_bootstrap = _get_json(f"{s10_url}/healthz", expected_status=401, token=bootstrap_token)
    s8_health = _get_json(f"{s8_url}/healthz", expected_status=200, token=health_token)
    s10_health = _get_json(f"{s10_url}/healthz", expected_status=200, token=health_token)
    s10_mint_with_health = _post_json(
        f"{s10_url}/v1/runtime-identities",
        {"caller_id": "m0-spine-launch"},
        expected_status=401,
        token=health_token,
    )
    s8_write_with_health = _post_json(
        f"{s8_url}/v1/artifacts",
        {},
        expected_status=401,
        token=health_token,
    )
    errors = {
        "s8_health_no_auth": s8_health_no_auth["error"],
        "s10_scope_no_auth": s10_scope_no_auth["error"],
        "s8_health_bootstrap": s8_health_bootstrap["error"],
        "s10_health_bootstrap": s10_health_bootstrap["error"],
        "s10_mint_with_health": s10_mint_with_health["error"],
        "s8_write_with_health": s8_write_with_health["error"],
    }
    if any(error != "Unauthorized" for error in errors.values()):
        raise AssertionError(f"unexpected auth denial payloads: {errors}")
    if s8_health["status"] != "ok" or s10_health["status"] != "ok":
        raise AssertionError(f"unexpected health payloads: s8={s8_health}, s10={s10_health}")
    if s8_health.get("ledger_writer") != "rust-subprocess":
        raise AssertionError(f"S8 did not activate the Rust ledger writer boundary: {s8_health}")
    if s8_health.get("checkpoint_signer") != "s10-http-insecure-local":
        raise AssertionError(f"S8 did not declare the local checkpoint signer transport policy: {s8_health}")
    if s8_health.get("report_verifier") != "argusverify":
        raise AssertionError(f"S8 did not activate the C3 report verifier: {s8_health}")
    if s8_health.get("report_verifier_trust_store") != "s10-http-insecure-local":
        raise AssertionError(f"S8 did not use the S10 HTTP verifier-key trust store: {s8_health}")
    if s10_health.get("checkpoint_signer") != "s10-kms":
        raise AssertionError(f"S10 did not activate the KMS checkpoint signer: {s10_health}")
    if s10_health.get("verifier_key_provider") != "s10-kms":
        raise AssertionError(f"S10 did not activate the KMS verifier-key provider: {s10_health}")
    if s10_health.get("token_signer") != "s10-kms-ed25519":
        raise AssertionError(f"S10 did not activate the Ed25519 KMS token signer: {s10_health}")
    if s10_health.get("token_signature_algorithm") != "ed25519":
        raise AssertionError(f"S10 did not activate Ed25519 token signatures: {s10_health}")
    if s10_health.get("token_verifier") != "offline-ed25519-public":
        raise AssertionError(f"S10 did not activate public-key offline token verification: {s10_health}")
    if s10_health.get("token_revocation_store") != "file":
        raise AssertionError(f"S10 did not activate file-backed token revocation state: {s10_health}")
    if s10_health.get("quota_ledger") != "postgres":
        raise AssertionError(f"S10 did not activate the Postgres quota ledger: {s10_health}")
    if s10_health.get("price_table") != "0.1.0":
        raise AssertionError(f"S10 did not activate the signed M0 price table: {s10_health}")
    if s10_health.get("price_table_signer_key_id") != "argus-m0-price-table":
        raise AssertionError(f"S10 did not report the M0 price table signer: {s10_health}")
    if s10_health.get("resource_meter") != "docker-api-cgroup":
        raise AssertionError(f"S10 did not activate the Docker API cgroup resource meter: {s10_health}")
    if float(s10_health.get("meter_interval_s", 999)) > 5:
        raise AssertionError(f"S10 resource meter cadence exceeds the S10 bound: {s10_health}")
    if float(s10_health.get("meter_gap_halt_s", 0)) < float(s10_health.get("meter_interval_s", 999)):
        raise AssertionError(f"S10 meter gap halt threshold is below the meter cadence: {s10_health}")
    if s10_health.get("dcgm_available") is not False:
        raise AssertionError(f"S10 M0 no-GPU health must report dcgm_available=false: {s10_health}")
    if s10_health.get("nvidia_smi_available") is not False:
        raise AssertionError(f"S10 M0 no-GPU health must report nvidia_smi_available=false: {s10_health}")
    if int(s10_health.get("gpu_count") or 0) != 0:
        raise AssertionError(f"S10 M0 no-GPU health must report gpu_count=0: {s10_health}")
    if s10_health.get("mig_enabled") is not False:
        raise AssertionError(f"S10 M0 no-GPU health must report mig_enabled=false: {s10_health}")
    if int(s10_health.get("mig_instance_count") or 0) != 0:
        raise AssertionError(f"S10 M0 no-GPU health must report mig_instance_count=0: {s10_health}")
    _record(
        evidence,
        "auth",
        "health checks use a separate bearer token from runtime bootstrap and runtime routes",
        {
            **errors,
            "s8_health": s8_health["status"],
            "s8_ledger_writer": s8_health["ledger_writer"],
            "s8_checkpoint_signer": s8_health["checkpoint_signer"],
            "s8_checkpoint_signer_transport_policy": "explicit-local-insecure-override",
            "s8_report_verifier": s8_health["report_verifier"],
            "s8_report_verifier_trust_store": s8_health["report_verifier_trust_store"],
            "s10_health": s10_health["status"],
            "s10_checkpoint_signer": s10_health["checkpoint_signer"],
            "s10_verifier_key_provider": s10_health["verifier_key_provider"],
            "s10_verifier_key_epoch": s10_health["verifier_key_epoch"],
            "s10_token_signer": s10_health["token_signer"],
            "s10_token_signature_algorithm": s10_health["token_signature_algorithm"],
            "s10_token_verifier": s10_health["token_verifier"],
            "s10_token_revocation_store": s10_health["token_revocation_store"],
            "s10_quota_ledger": s10_health["quota_ledger"],
            "s10_price_table": s10_health["price_table"],
            "s10_price_table_signer_key_id": s10_health["price_table_signer_key_id"],
            "s10_resource_meter": s10_health["resource_meter"],
            "s10_meter_interval_s": s10_health["meter_interval_s"],
            "s10_meter_gap_halt_s": s10_health["meter_gap_halt_s"],
            "s10_dcgm_available": s10_health["dcgm_available"],
            "s10_nvidia_smi_available": s10_health["nvidia_smi_available"],
            "s10_gpu_count": s10_health["gpu_count"],
            "s10_gpu_models": s10_health["gpu_models"],
            "s10_mig_enabled": s10_health["mig_enabled"],
            "s10_mig_instance_count": s10_health["mig_instance_count"],
            "s10_gpu_telemetry_source": s10_health["gpu_telemetry_source"],
        },
    )
    return str(s10_health["checkpoint_signer"])


def _battery_forged_scope_token_denied(
    evidence: dict[str, Any],
    s10_url: str,
    scope_json: dict[str, Any],
    *,
    token: str,
) -> None:
    forged_scope = {**scope_json, "signature": "ed25519:" + "0" * 128}
    response = _post_json(
        f"{s10_url}/v1/store/artifacts",
        {
            "scope_token": forged_scope,
            "kind": "model",
            "payload": {"weights": [8]},
            "producer": {"subsystem": "S2", "version": "0.0.0"},
            "lineage": {"input_refs": [], "code_ref": "git:model", "environment_digest": "oci:model"},
        },
        expected_status=401,
        token=token,
    )
    if response["error"] != "TokenInvalidError":
        raise AssertionError(f"unexpected forged-token denial error: {response}")
    _record(evidence, "scope-forged", "brokered write with forged scope token rejected fail-closed", response)


def _battery_revoked_scope_token_denied(
    evidence: dict[str, Any],
    s10_url: str,
    *,
    token: str,
) -> None:
    scope_json = _mint_store_scope(s10_url=s10_url, token=token)
    started = time.monotonic()
    revoke_response = _post_json(
        f"{s10_url}/v1/tokens:revoke",
        {"token_type": "scope", "token": scope_json},
        expected_status=200,
        token=token,
    )
    denied_response = _post_json(
        f"{s10_url}/v1/store/artifacts",
        {
            "scope_token": scope_json,
            "kind": "model",
            "payload": {"weights": [9]},
            "producer": {"subsystem": "S2", "version": "0.0.0"},
            "lineage": {"input_refs": [], "code_ref": "git:revoked", "environment_digest": "oci:revoked"},
        },
        expected_status=401,
        token=token,
    )
    denied_after_s = time.monotonic() - started
    if denied_response.get("error") != "TokenInvalidError":
        raise AssertionError(f"unexpected revoked-token denial error: {denied_response}")
    if denied_after_s > TOKEN_REVOCATION_PROPAGATION_SLO_S:
        raise AssertionError(
            "revoked scope token was not denied within the propagation SLO: "
            f"elapsed={denied_after_s:.6f}s slo={TOKEN_REVOCATION_PROPAGATION_SLO_S:.6f}s"
        )
    _record(
        evidence,
        "scope-revoked",
        "file-backed S10 revocation state denies a revoked scope token on the broker route within the SLO",
        {
            "token_type": "scope",
            "revocation_store": revoke_response["revocation_store"],
            "revoked_token_id": revoke_response["revoked_token_id"],
            "denial_error": denied_response["error"],
            "denial_message": denied_response.get("message"),
            "denied_after_s": round(denied_after_s, 6),
            "propagation_slo_s": TOKEN_REVOCATION_PROPAGATION_SLO_S,
            "route": "POST /v1/store/artifacts",
        },
    )


def _battery_revoked_budget_token_denied(
    evidence: dict[str, Any],
    s10_url: str,
    *,
    image: str,
    token: str,
) -> None:
    budget_json = _post_json(
        f"{s10_url}/v1/budget-tokens",
        {},
        expected_status=201,
        token=token,
    )
    scope_json = _post_json(
        f"{s10_url}/v1/scope-tokens",
        {},
        expected_status=201,
        token=token,
    )
    launch = _launch_request_json(
        job_id="m0-spine-job",
        image=image,
        budget=budget_json,
        scope=scope_json,
        args=("-c", "echo should-not-run"),
        env={},
        env_allowlist=(),
        wallclock_s=1,
    )
    started = time.monotonic()
    revoke_response = _post_json(
        f"{s10_url}/v1/tokens:revoke",
        {"token_type": "budget", "token": budget_json},
        expected_status=200,
        token=token,
    )
    denied_response = _post_json(
        f"{s10_url}/v1/sandboxes:launch",
        launch,
        expected_status=401,
        token=token,
    )
    denied_after_s = time.monotonic() - started
    if denied_response.get("error") != "TokenInvalidError":
        raise AssertionError(f"unexpected revoked-budget denial error: {denied_response}")
    if denied_after_s > TOKEN_REVOCATION_PROPAGATION_SLO_S:
        raise AssertionError(
            "revoked budget token was not denied within the propagation SLO: "
            f"elapsed={denied_after_s:.6f}s slo={TOKEN_REVOCATION_PROPAGATION_SLO_S:.6f}s"
        )
    _record(
        evidence,
        "budget-revoked",
        "file-backed S10 revocation state denies a revoked budget token on the launch route within the SLO",
        {
            "token_type": "budget",
            "revocation_store": revoke_response["revocation_store"],
            "revoked_token_id": revoke_response["revoked_token_id"],
            "denial_error": denied_response["error"],
            "denial_message": denied_response.get("message"),
            "denied_after_s": round(denied_after_s, 6),
            "propagation_slo_s": TOKEN_REVOCATION_PROPAGATION_SLO_S,
            "route": "POST /v1/sandboxes:launch",
        },
    )


def _battery_revoked_inflight_sandbox_halted(
    evidence: dict[str, Any],
    s10_url: str,
    *,
    s8_url: str,
    image: str,
    token: str,
    read_token: str,
) -> None:
    budget_json = _post_json(
        f"{s10_url}/v1/budget-tokens",
        {},
        expected_status=201,
        token=token,
    )
    scope_json = _post_json(
        f"{s10_url}/v1/scope-tokens",
        {},
        expected_status=201,
        token=token,
    )
    launch = _launch_request_json(
        job_id="m0-spine-job",
        image=image,
        budget=budget_json,
        scope=scope_json,
        args=("-c", "while true; do echo in-flight-before-revoke; sleep 0.2; done"),
        env={},
        env_allowlist=(),
        wallclock_s=10,
    )
    launch_result: dict[str, Any] = {}
    launch_error: list[BaseException] = []

    def launch_in_background() -> None:
        try:
            launch_result.update(
                _post_json(
                    f"{s10_url}/v1/sandboxes:launch",
                    launch,
                    expected_status=201,
                    token=token,
                    timeout=20,
                )
            )
        except BaseException as exc:  # pragma: no cover - surfaced in caller thread
            launch_error.append(exc)

    thread = threading.Thread(target=launch_in_background, daemon=True)
    thread.start()
    time.sleep(1.0)
    started = time.monotonic()
    revoke_response = _post_json(
        f"{s10_url}/v1/tokens:revoke",
        {"token_type": "budget", "token": budget_json},
        expected_status=200,
        token=token,
    )
    thread.join(timeout=TOKEN_REVOCATION_PROPAGATION_SLO_S + 8.0)
    halted_after_revoke_s = time.monotonic() - started
    if thread.is_alive():
        raise AssertionError(
            "in-flight sandbox did not halt after budget token revocation within the propagation window"
        )
    if launch_error:
        raise AssertionError("in-flight revoked launch request failed unexpectedly") from launch_error[0]
    if halted_after_revoke_s > TOKEN_REVOCATION_PROPAGATION_SLO_S:
        raise AssertionError(
            "in-flight revoked sandbox halt exceeded the propagation SLO: "
            f"elapsed={halted_after_revoke_s:.6f}s slo={TOKEN_REVOCATION_PROPAGATION_SLO_S:.6f}s"
        )
    handle = launch_result.get("handle") or {}
    events = launch_result.get("audit_events") or []
    stderr = str(launch_result.get("stderr") or "")
    if handle.get("state") != "TIMED_OUT" or launch_result.get("timed_out") is not True:
        raise AssertionError(f"in-flight revoked sandbox did not return TIMED_OUT: {launch_result}")
    if "token_revoked" not in stderr:
        raise AssertionError(f"in-flight revoked sandbox stderr did not identify token_revoked: {launch_result}")
    if "token.revocation_halt" not in events or "meter.halt" not in events:
        raise AssertionError(f"in-flight revoked sandbox missing revocation halt audit events: {launch_result}")
    launch_provenance_ref = handle.get("launch_provenance_ref")
    if not isinstance(launch_provenance_ref, str) or not launch_provenance_ref:
        raise AssertionError(f"in-flight revoked sandbox missing launch provenance: {launch_result}")
    spend_final = _battery_spend_final(
        s8_url=s8_url,
        read_token=read_token,
        job_id="m0-spine-job",
        launch_provenance_ref=launch_provenance_ref,
        expected_state="TIMED_OUT",
    )
    if "token_revoked" not in spend_final["meter_breached_dimensions"]:
        raise AssertionError(f"spend.final missing token_revoked metering dimension: {spend_final}")
    if spend_final["meter_halted_by_meter"] is not True:
        raise AssertionError(f"spend.final did not mark the token revocation halt as metered: {spend_final}")
    _record(
        evidence,
        "inflight-revoked",
        "deployed S10 halts an in-flight sandbox after budget token revocation and records revocation audit evidence",
        {
            "token_type": "budget",
            "revocation_store": revoke_response["revocation_store"],
            "revoked_token_id": revoke_response["revoked_token_id"],
            "halted_after_revoke_s": round(halted_after_revoke_s, 6),
            "propagation_slo_s": TOKEN_REVOCATION_PROPAGATION_SLO_S,
            "launch_handle_state": handle["state"],
            "launch_timed_out": launch_result["timed_out"],
            "launch_stderr": stderr,
            "audit_events": events,
            "launch_provenance_ref": launch_provenance_ref,
            "spend_final_ref": spend_final["artifact_ref"],
            "spend_final_state": spend_final["final_state"],
            "spend_final_meter_halted_by_meter": spend_final["meter_halted_by_meter"],
            "spend_final_meter_breached_dimensions": spend_final["meter_breached_dimensions"],
            "spend_final_partial_result_captured": spend_final["partial_result_captured"],
        },
    )


def _battery_s8_capability_scopes(
    evidence: dict[str, Any],
    s8_url: str,
    *,
    read_token: str,
    write_token: str,
) -> None:
    protected_ref = parse.quote("c4://artifact/not-yet-written", safe="")
    read_query = _get_json(f"{s8_url}/v1/artifacts?page_size=1", expected_status=200, token=read_token)
    write_query = _get_json(f"{s8_url}/v1/artifacts?page_size=1", expected_status=403, token=write_token)
    write_record = _get_json(
        f"{s8_url}/v1/artifacts/{protected_ref}/record",
        expected_status=403,
        token=write_token,
    )
    write_payload = _get_json(
        f"{s8_url}/v1/artifacts/{protected_ref}/payload",
        expected_status=403,
        token=write_token,
    )
    write_repro_status = _get_json(
        f"{s8_url}/v1/reproducibility-status/{protected_ref}",
        expected_status=403,
        token=write_token,
    )
    unauth_record = _get_json(
        f"{s8_url}/v1/artifacts/{protected_ref}/record",
        expected_status=401,
        token=None,
    )
    read_write = _post_json(
        f"{s8_url}/v1/reproducibility-checks",
        {
            "artifact_ref": "c4://artifact/not-yet-written",
            "rerun_content_hash": "blake3:" + "0" * 64,
            "tolerance_id": "capability-negative",
        },
        expected_status=403,
        token=read_token,
    )
    capability_errors = (write_query, write_record, write_payload, write_repro_status, read_write)
    if any(error.get("error") != "CapabilityDenied" for error in capability_errors):
        raise AssertionError(f"S8 capability gates did not fail closed: {capability_errors}")
    if unauth_record.get("error") != "Unauthorized":
        raise AssertionError(f"S8 unauthenticated read did not fail closed: {unauth_record}")
    _record(
        evidence,
        "s8-capability",
        "S8 HTTP query, record, payload, reproducibility-status, and reproducibility-write routes enforce capabilities before store access",
        {
            "read_query_records": len(read_query["records"]),
            "write_token_query_error": write_query["error"],
            "write_token_record_error": write_record["error"],
            "write_token_payload_error": write_payload["error"],
            "write_token_repro_status_error": write_repro_status["error"],
            "unauth_record_error": unauth_record["error"],
            "read_token_repro_write_error": read_write["error"],
        },
    )


def _mint_store_scope(*, s10_url: str, token: str) -> dict[str, Any]:
    return _post_json(
        f"{s10_url}/v1/scope-tokens",
        {},
        expected_status=201,
        token=token,
    )


def _battery_direct_s8_write_denied(evidence: dict[str, Any], s8_url: str, *, token: str) -> None:
    response = _post_json(
        f"{s8_url}/v1/artifacts",
        {
            "kind": "model",
            "payload": {"weights": [9]},
            "producer": {"subsystem": "S2", "version": "0.0.0"},
            "lineage": {"input_refs": [], "code_ref": "git:model", "environment_digest": "oci:model"},
        },
        expected_status=403,
        token=token,
    )
    if response["error"] != "DirectWriteDenied":
        raise AssertionError(f"unexpected direct-write denial error: {response}")
    _record(evidence, "f-direct", "direct S8 HTTP artifact write denied", response)


def _battery_b_incomplete_lineage(
    evidence: dict[str, Any],
    s10_url: str,
    scope_json: dict[str, Any],
    *,
    token: str,
) -> None:
    response = _post_json(
        f"{s10_url}/v1/store/artifacts",
        {
            "scope_token": scope_json,
            "kind": "model",
            "payload": {"weights": [0]},
            "producer": {"subsystem": "S2", "version": "0.0.0"},
            "lineage": {"input_refs": [], "code_ref": "", "environment_digest": ""},
        },
        expected_status=400,
        token=token,
    )
    if response["error"] != "IncompleteLineageError":
        raise AssertionError(f"unexpected incomplete-lineage error: {response}")
    _record(evidence, "b", "brokered incomplete lineage write rejected fail-closed", response)


def _battery_c_write_once(
    evidence: dict[str, Any],
    s10_url: str,
    scope_json: dict[str, Any],
    *,
    token: str,
) -> None:
    body = {
        "scope_token": scope_json,
        "artifact_ref": "c4://m0-spine/overwrite-guard",
        "kind": "model",
        "payload": {"weights": [1]},
        "producer": {"subsystem": "S2", "version": "0.0.0"},
        "lineage": {"input_refs": [], "code_ref": "git:model", "environment_digest": "oci:model"},
    }
    first = _post_json(f"{s10_url}/v1/store/artifacts", body, expected_status=201, token=token)
    second = _post_json(
        f"{s10_url}/v1/store/artifacts",
        {**body, "payload": {"weights": [2]}},
        expected_status=400,
        token=token,
    )
    if second["error"] != "WriteOnceViolationError":
        raise AssertionError(f"unexpected overwrite error: {second}")
    _record(
        evidence,
        "c",
        "brokered write-once overwrite blocked",
        {"artifact_ref": first["artifact_ref"], "error": second},
    )


def _battery_dataset_registry_service(
    evidence: dict[str, Any],
    *,
    s10_url: str,
    s8_url: str,
    dataset_scope_json: dict[str, Any],
    dataset_token: str,
    read_token: str,
    verifier_label_token: str,
    write_token: str,
) -> None:
    dataset_id = "m0-dataset-registry"
    version = "1.0.0"
    dataset_artifact = _post_json(
        f"{s10_url}/v1/store/artifacts",
        {
            "scope_token": dataset_scope_json,
            "kind": "dataset",
            "payload": {
                "dataset_id": dataset_id,
                "version": version,
                "rows": [{"id": "row-1"}, {"id": "row-2"}],
            },
            "producer": {"subsystem": "S8", "version": "0.0.0"},
            "lineage": {
                "input_refs": [],
                "code_ref": "git:m0-dataset-registry",
                "environment_digest": "oci:m0-dataset-registry",
                "seeds": ["dataset-seed-1"],
            },
        },
        expected_status=201,
        token=dataset_token,
    )
    register_body = {
        "dataset_id": dataset_id,
        "version": version,
        "dataset_artifact_ref": dataset_artifact["artifact_ref"],
        "contamination_index_version": "contamination-m0-2026-07-03",
        "splits": [
            {
                "split_id": "train",
                "role": "train",
                "content_hash": "blake3:" + "a" * 64,
                "row_count": 2,
                "schema_ref": "c4://schemas/m0-dataset/train",
                "access_scope": "agent-readable",
            },
            {
                "split_id": "blind",
                "role": "blind",
                "content_hash": "blake3:" + "b" * 64,
                "row_count": 1,
                "schema_ref": "c4://schemas/m0-dataset/blind",
                "access_scope": "verifier-only",
                "label_seal_ref": "c4://labels/m0-dataset/blind",
            },
        ],
    }
    read_token_register = _post_json(
        f"{s8_url}/v1/datasets",
        register_body,
        expected_status=403,
        token=read_token,
    )
    registered = _post_json(
        f"{s8_url}/v1/datasets",
        register_body,
        expected_status=201,
        token=dataset_token,
    )
    latest = _get_json(f"{s8_url}/v1/datasets/{dataset_id}", token=read_token)
    versions = _get_json(f"{s8_url}/v1/datasets/{dataset_id}/versions", token=read_token)
    write_token_get = _get_json(
        f"{s8_url}/v1/datasets/{dataset_id}",
        expected_status=403,
        token=write_token,
    )
    unauth_get = _get_json(
        f"{s8_url}/v1/datasets/{dataset_id}",
        expected_status=401,
        token=None,
    )
    train_resolution = _get_json(
        f"{s8_url}/v1/datasets/{dataset_id}/splits/train/resolve?version={parse.quote(version)}",
        token=read_token,
    )
    blind_read_resolution = _get_json(
        f"{s8_url}/v1/datasets/{dataset_id}/splits/blind/resolve?version={parse.quote(version)}",
        expected_status=403,
        token=read_token,
    )
    blind_verifier_resolution = _get_json(
        f"{s8_url}/v1/datasets/{dataset_id}/splits/blind/resolve?version={parse.quote(version)}",
        token=verifier_label_token,
    )
    write_token_resolution = _get_json(
        f"{s8_url}/v1/datasets/{dataset_id}/splits/blind/resolve?version={parse.quote(version)}",
        expected_status=403,
        token=write_token,
    )
    unauth_resolution = _get_json(
        f"{s8_url}/v1/datasets/{dataset_id}/splits/blind/resolve?version={parse.quote(version)}",
        expected_status=401,
        token=None,
    )
    blind_split = next(split for split in latest["splits"] if split["split_id"] == "blind")
    masked_blind_split = "content_hash" not in blind_split and "label_seal_ref" not in blind_split
    provenance_ref = registered["provenance_ref"]["artifact_ref"]
    if provenance_ref != dataset_artifact["artifact_ref"]:
        raise AssertionError(f"dataset registry did not bind the S10-broker-written artifact: {registered}")
    if latest["version"] != version or versions["versions"] != [version]:
        raise AssertionError(f"dataset registry version lookup failed: latest={latest}, versions={versions}")
    if not masked_blind_split:
        raise AssertionError(f"dataset registry leaked verifier-only split material: {latest}")
    if read_token_register.get("error") != "CapabilityDenied" or write_token_get.get("error") != "CapabilityDenied":
        raise AssertionError(
            "dataset registry capability gates did not fail closed: "
            f"read_token_register={read_token_register}, write_token_get={write_token_get}"
        )
    if unauth_get.get("error") != "Unauthorized":
        raise AssertionError(f"dataset registry unauthenticated read did not fail closed: {unauth_get}")
    if train_resolution.get("feature_blob_ref") != "blake3:" + "a" * 64 or train_resolution.get("label_blob_ref") is not None:
        raise AssertionError(f"agent-readable train split did not resolve as feature-only: {train_resolution}")
    if (
        blind_read_resolution.get("category") != "SCOPE_DENIED"
        or "c4://labels/m0-dataset/blind" in blind_read_resolution.get("message", "")
    ):
        raise AssertionError(f"blind split read-token denial leaked or used wrong category: {blind_read_resolution}")
    if (
        blind_verifier_resolution.get("feature_blob_ref") != "blake3:" + "b" * 64
        or blind_verifier_resolution.get("label_blob_ref") != "c4://labels/m0-dataset/blind"
    ):
        raise AssertionError(f"verifier-label token did not resolve blind label seal: {blind_verifier_resolution}")
    if write_token_resolution.get("error") != "CapabilityDenied":
        raise AssertionError(f"write token unexpectedly resolved blind split: {write_token_resolution}")
    if unauth_resolution.get("error") != "Unauthorized":
        raise AssertionError(f"unauthenticated split resolve did not fail closed: {unauth_resolution}")
    _record(
        evidence,
        "dataset-registry",
        "S10 broker wrote a dataset C4 artifact and S8 dataset registry HTTP APIs registered, read, listed, masked, and resolved splits through capability gates",
        {
            "dataset_id": dataset_id,
            "version": version,
            "dataset_artifact_ref": dataset_artifact["artifact_ref"],
            "registered_artifact_ref": provenance_ref,
            "versions": versions["versions"],
            "masked_blind_split": masked_blind_split,
            "read_token_register_error": read_token_register["error"],
            "write_token_get_error": write_token_get["error"],
            "unauth_get_error": unauth_get["error"],
            "train_resolve_feature_blob_ref": train_resolution["feature_blob_ref"],
            "train_resolve_label_blob_ref": train_resolution["label_blob_ref"],
            "blind_read_resolve_category": blind_read_resolution["category"],
            "blind_read_resolve_message_leaked_label_ref": "c4://labels/m0-dataset/blind"
            in blind_read_resolution.get("message", ""),
            "blind_verifier_resolve_feature_blob_ref": blind_verifier_resolution["feature_blob_ref"],
            "blind_verifier_resolve_label_blob_ref": blind_verifier_resolution["label_blob_ref"],
            "blind_verifier_resolve_audit_event_id": blind_verifier_resolution["audit_event_id"],
            "write_token_resolve_error": write_token_resolution["error"],
            "unauth_resolve_error": unauth_resolution["error"],
        },
    )


def _battery_deployed_report_verifier(
    evidence: dict[str, Any],
    s10_url: str,
    *,
    verifier_scope_json: dict[str, Any],
    verifier_token: str,
    model_scope_json: dict[str, Any],
    model_token: str,
    verifier_signing_key: bytes,
    verifier_key_auth_token: str,
) -> None:
    signer = C3ReportSigner(key_id=M0_C3_VERIFIER_KEY_ID, secret=verifier_signing_key)
    signed_report = signer.sign(_m0_validation_report(claim_tier="recapitulated-known"))
    _battery_s10_verifier_key_store(
        evidence,
        s10_url=s10_url,
        signed_report=signed_report,
        verifier_key_auth_token=verifier_key_auth_token,
    )
    report_record = _post_json(
        f"{s10_url}/v1/store/artifacts",
        {
            "scope_token": verifier_scope_json,
            "kind": "report",
            "payload": signed_report,
            "producer": {"subsystem": "S3", "version": "0.0.0"},
            "lineage": {"input_refs": [], "code_ref": "git:m0-verifier", "environment_digest": "oci:m0-verifier"},
        },
        expected_status=201,
        token=verifier_token,
    )
    promoted = _post_json(
        f"{s10_url}/v1/store/artifacts",
        {
            "scope_token": model_scope_json,
            "kind": "model",
            "payload": {
                "weights": [3, 2, 1],
                "source": "signed-report",
                "uncertainty_tag": {"kind": "interval", "radius": 0.1},
            },
            "producer": {"subsystem": "S2", "version": "0.0.0"},
            "lineage": {"input_refs": [], "code_ref": "git:m0-promoted", "environment_digest": "oci:m0-promoted"},
            "claim_tier": "recapitulated-known",
            "validation_report_ref": report_record["artifact_ref"],
        },
        expected_status=201,
        token=model_token,
    )
    tampered = signer.sign(_m0_validation_report(claim_tier="recapitulated-known"))
    tampered["aggregate"]["score"] = 0.1
    tampered_rejected = _post_json(
        f"{s10_url}/v1/store/artifacts",
        {
            "scope_token": verifier_scope_json,
            "kind": "report",
            "payload": tampered,
            "producer": {"subsystem": "S3", "version": "0.0.0"},
            "lineage": {"input_refs": [], "code_ref": "git:m0-tampered", "environment_digest": "oci:m0-verifier"},
        },
        expected_status=400,
        token=verifier_token,
    )
    mismatch_rejected = _post_json(
        f"{s10_url}/v1/store/artifacts",
        {
            "scope_token": model_scope_json,
            "kind": "model",
            "payload": {"weights": [9], "uncertainty_tag": {"kind": "interval", "radius": 0.1}},
            "producer": {"subsystem": "S2", "version": "0.0.0"},
            "lineage": {"input_refs": [], "code_ref": "git:m0-mismatch", "environment_digest": "oci:m0-promoted"},
            "claim_tier": "novel-needs-human",
            "validation_report_ref": report_record["artifact_ref"],
        },
        expected_status=400,
        token=model_token,
    )
    if "signature_invalid" not in str(tampered_rejected.get("message", "")):
        raise AssertionError(f"tampered report was not rejected by the deployed verifier: {tampered_rejected}")
    if "tier must match validation report claim_tier" not in str(mismatch_rejected.get("message", "")):
        raise AssertionError(f"tier mismatch was not rejected by the deployed verifier: {mismatch_rejected}")
    _record(
        evidence,
        "report-verifier",
        "deployed S8 Postgres path used argusverify for signed-report tier coupling",
        {
            "report_ref": report_record["artifact_ref"],
            "promoted_model_ref": promoted["artifact_ref"],
            "claim_tier": promoted["claim_tier"],
            "tampered_report_rejected": tampered_rejected["message"],
            "tier_mismatch_rejected": mismatch_rejected["message"],
        },
    )


def _battery_s10_verifier_key_store(
    evidence: dict[str, Any],
    *,
    s10_url: str,
    signed_report: dict[str, Any],
    verifier_key_auth_token: str,
) -> None:
    unauth = _get_json(f"{s10_url}/v1/internal/verifier-keys", expected_status=401)
    snapshot = _get_json(
        f"{s10_url}/v1/internal/verifier-keys",
        expected_status=200,
        token=verifier_key_auth_token,
    )
    keys = snapshot.get("keys")
    if not isinstance(keys, list):
        raise AssertionError(f"S10 verifier key snapshot did not return keys: {snapshot}")
    key_ids = {key.get("key_id") for key in keys if isinstance(key, dict)}
    if M0_C3_VERIFIER_KEY_ID not in key_ids:
        raise AssertionError(f"S10 verifier key snapshot missing M0 key: {snapshot}")
    if any(isinstance(key, dict) and "secret" in key for key in keys):
        raise AssertionError(f"S10 verifier key snapshot exposed secret material: {snapshot}")
    unsigned = json.loads(json.dumps(signed_report))
    unsigned["signature"]["value"] = ""
    signature_value = signed_report["signature"]["value"]
    accepted = _post_json(
        f"{s10_url}/v1/internal/verifier-keys:verify",
        {
            "key_id": M0_C3_VERIFIER_KEY_ID,
            "report_with_empty_signature": unsigned,
            "signature_value": signature_value,
        },
        expected_status=200,
        token=verifier_key_auth_token,
    )
    bad_signature = _post_json(
        f"{s10_url}/v1/internal/verifier-keys:verify",
        {
            "key_id": M0_C3_VERIFIER_KEY_ID,
            "report_with_empty_signature": unsigned,
            "signature_value": "hmac-sha256:" + "0" * 64,
        },
        expected_status=200,
        token=verifier_key_auth_token,
    )
    unknown_key = _post_json(
        f"{s10_url}/v1/internal/verifier-keys:verify",
        {
            "key_id": "unknown-verifier",
            "report_with_empty_signature": unsigned,
            "signature_value": signature_value,
        },
        expected_status=200,
        token=verifier_key_auth_token,
    )
    if accepted.get("result") != SIGNATURE_VERIFICATION_ACCEPTED:
        raise AssertionError(f"S10 verifier key store did not accept a valid signature: {accepted}")
    if bad_signature.get("result") != "signature_invalid":
        raise AssertionError(f"S10 verifier key store did not reject a bad signature: {bad_signature}")
    if unknown_key.get("result") != "unknown_key":
        raise AssertionError(f"S10 verifier key store did not reject an unknown key: {unknown_key}")
    _record(
        evidence,
        "verifier-key-store",
        "S10 verifier-key store exposes metadata-only snapshots and performs signature verification",
        {
            "provider": snapshot["provider"],
            "epoch": snapshot["epoch"],
            "key_ids": sorted(key_ids),
            "secret_exposed": False,
            "unauth_error": unauth["error"],
            "valid_result": accepted["result"],
            "bad_signature_result": bad_signature["result"],
            "unknown_key_result": unknown_key["result"],
        },
    )


def _battery_real_persistence(
    evidence: dict[str, Any],
    ports: dict[str, str],
    *,
    s8_url: str,
    token: str,
    checkpoint_signing_key: bytes,
    checkpoint_signer_provider_from_health: str,
) -> None:
    import psycopg
    from minio import Minio

    dsn = f"postgresql://argus:argus-dev-password@127.0.0.1:{ports['ARGUS_M0_POSTGRES_PORT']}/argus"
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM s8.schema_migration;")
            migration_count = int(cur.fetchone()[0])
            cur.execute("SELECT count(*) FROM s10.schema_migration;")
            s10_migration_count = int(cur.fetchone()[0])
            cur.execute("SELECT count(*) FROM s10.quota_ledger_entry;")
            s10_quota_ledger_entries = int(cur.fetchone()[0])
            cur.execute("SELECT count(*) FROM s10.quota_budget WHERE halted;")
            s10_quota_halted_budgets = int(cur.fetchone()[0])
            cur.execute(
                """
                SELECT COALESCE(bool_and(
                    ((remaining_after->>'compute_units')::double precision >= 0)
                    AND ((remaining_after->>'gpu_seconds')::double precision >= 0)
                    AND ((remaining_after->>'model_tokens')::double precision >= 0)
                    AND ((remaining_after->>'wallclock_s')::double precision >= 0)
                    AND ((remaining_after->>'cost_usd')::double precision >= 0)
                ), false)
                FROM s10.quota_ledger_entry;
                """
            )
            s10_quota_remaining_non_negative = bool(cur.fetchone()[0])
            cur.execute(
                """
                SELECT entry_type
                FROM s10.quota_ledger_entry
                GROUP BY entry_type
                ORDER BY entry_type;
                """
            )
            s10_quota_entry_types = [str(row[0]) for row in cur.fetchall()]
            cur.execute("SELECT count(*) FROM s8.artifact_record;")
            record_count = int(cur.fetchone()[0])
            cur.execute(
                """
                SELECT verdict, count(*)
                FROM s8.dataset_resolve_audit
                GROUP BY verdict
                ORDER BY verdict;
                """
            )
            dataset_resolve_audit_counts = {str(row[0]): int(row[1]) for row in cur.fetchall()}
            cur.execute(
                """
                SELECT count(*)
                FROM s8.dataset_resolve_audit
                WHERE dataset_id = 'm0-dataset-registry'
                  AND split_id = 'blind'
                  AND verdict = 'DENIED'
                  AND label_seal_ref IS NULL;
                """
            )
            dataset_resolve_denied_blind_count = int(cur.fetchone()[0])
            cur.execute("SELECT count(*) FROM s8.ledger_leaf;")
            leaf_count = int(cur.fetchone()[0])
            cur.execute("SELECT count(*) FROM s8.merkle_checkpoint;")
            checkpoint_count = int(cur.fetchone()[0])
            cur.execute(
                """
                SELECT seq, root, signature, signer_key_id
                FROM s8.merkle_checkpoint
                ORDER BY seq DESC
                LIMIT 1;
                """
            )
            latest_checkpoint = cur.fetchone()
            cur.execute("SELECT artifact_id, record_hash FROM s8.artifact_record ORDER BY merkle_seq;")
            record_hash_rows = [(str(row[0]), str(row[1])) for row in cur.fetchall()]
    append_only_denials = _postgres_append_only_denials(dsn)
    record_hashes_match = _postgres_record_hashes_match_refreshed_records(
        record_hash_rows,
        s8_url=s8_url,
        token=token,
    )
    minio = Minio(
        f"127.0.0.1:{ports['ARGUS_M0_MINIO_PORT']}",
        access_key="argus",
        secret_key="argus-dev-password",
        secure=False,
    )
    object_count = sum(1 for _ in minio.list_objects("argus-s8-objects", recursive=True))
    checkpoint_signature_valid = False
    checkpoint_sequence = 0
    checkpoint_signer_key_id = ""
    if latest_checkpoint is not None:
        checkpoint_sequence = int(latest_checkpoint[0])
        checkpoint_root = str(latest_checkpoint[1])
        checkpoint_signature = str(latest_checkpoint[2])
        checkpoint_signer_key_id = str(latest_checkpoint[3])
        checkpoint_signature_valid = hmac.compare_digest(
            checkpoint_signature,
            _s8_checkpoint_signature(
                sequence=checkpoint_sequence,
                root=checkpoint_root,
                signer_key_id=checkpoint_signer_key_id,
                signing_key=checkpoint_signing_key,
            ),
        )
    if (
        migration_count < 1
        or record_count < 2
        or leaf_count < 2
        or checkpoint_count != leaf_count
        or checkpoint_sequence != leaf_count
        or checkpoint_signer_key_id != "argus-m0-s8-checkpoint"
        or not checkpoint_signature_valid
        or object_count < 2
        or dataset_resolve_audit_counts.get("DENIED", 0) < 1
        or dataset_resolve_denied_blind_count < 1
        or not all(append_only_denials.values())
        or not record_hashes_match
        or s10_migration_count < 1
        or s10_quota_ledger_entries < 4
        or s10_quota_halted_budgets < 1
        or not s10_quota_remaining_non_negative
        or not {"register", "reserve", "consume", "release", "halt"}.issubset(s10_quota_entry_types)
    ):
        raise AssertionError(
            "Postgres/MinIO persistence did not record expected deployed S8 artifacts: "
            f"migrations={migration_count} records={record_count} leaves={leaf_count} "
            f"checkpoints={checkpoint_count} checkpoint_sequence={checkpoint_sequence} "
            f"checkpoint_signer={checkpoint_signer_key_id} checkpoint_signature_valid={checkpoint_signature_valid} "
            f"dataset_resolve_audit_counts={dataset_resolve_audit_counts} "
            f"dataset_resolve_denied_blind_count={dataset_resolve_denied_blind_count} "
            f"objects={object_count} append_only_denials={append_only_denials} "
            f"record_hashes_match_refreshed_records={record_hashes_match} "
            f"s10_migrations={s10_migration_count} s10_quota_entries={s10_quota_ledger_entries} "
            f"s10_quota_halted_budgets={s10_quota_halted_budgets} "
            f"s10_quota_remaining_non_negative={s10_quota_remaining_non_negative} "
            f"s10_quota_entry_types={s10_quota_entry_types}"
        )
    audit_root_tamper_denial = _postgres_audit_root_tamper_denial(dsn, s8_url=s8_url, token=token)
    _record(
        evidence,
        "persist",
        "deployed S8 wrote C4 metadata and S10 wrote quota history to Postgres append-only ledgers with MinIO payloads and recomputable record hashes",
        {
            "schema_migrations": migration_count,
            "s10_schema_migrations": s10_migration_count,
            "s10_quota_ledger_entries": s10_quota_ledger_entries,
            "s10_quota_halted_budgets": s10_quota_halted_budgets,
            "s10_quota_remaining_non_negative": s10_quota_remaining_non_negative,
            "s10_quota_entry_types": s10_quota_entry_types,
            "artifact_records": record_count,
            "dataset_resolve_audit_counts": dataset_resolve_audit_counts,
            "dataset_resolve_denied_blind_count": dataset_resolve_denied_blind_count,
            "ledger_leaves": leaf_count,
            "merkle_checkpoints": checkpoint_count,
            "latest_checkpoint_sequence": checkpoint_sequence,
            "checkpoint_signer_key_id": checkpoint_signer_key_id,
            "checkpoint_signer_provider_asserted_by_s10_health": checkpoint_signer_provider_from_health,
            "checkpoint_signature_valid": checkpoint_signature_valid,
            "minio_objects": object_count,
            "record_hashes_match_refreshed_records": record_hashes_match,
            "audit_root_tamper_denied": audit_root_tamper_denial,
            **append_only_denials,
        },
    )


def _s8_checkpoint_signature(
    *,
    sequence: int,
    root: str,
    signer_key_id: str,
    signing_key: bytes,
) -> str:
    payload = s8_checkpoint_signature_payload(sequence=sequence, root=root, signer_key_id=signer_key_id)
    return "hmac-sha256:" + hmac.new(signing_key, payload.encode("utf-8"), sha256).hexdigest()


def _decimal_wire(value: Decimal) -> str:
    normalized = value.normalize()
    if normalized == normalized.to_integral():
        return format(normalized.quantize(Decimal("1")), "f")
    return format(normalized, "f")


def _postgres_record_hashes_match_refreshed_records(
    rows: list[tuple[str, str]],
    *,
    s8_url: str,
    token: str,
) -> bool:
    for artifact_id, record_hash in rows:
        record_json = _get_json(f"{s8_url}/v1/artifacts/{artifact_id}/record", token=token)
        record = _artifact_record_from_json(record_json)
        if hash_json(asdict(record)) != record_hash:
            return False
    return True


def _postgres_audit_root_tamper_denial(
    dsn: str,
    *,
    s8_url: str,
    token: str,
) -> dict[str, Any]:
    import psycopg

    def audit_slice_url(
        artifact_refs: tuple[str, ...],
        *,
        page_size: int | None = None,
        page_token: int | None = None,
    ) -> str:
        params: list[tuple[str, str]] = [("artifact_ref", artifact_ref) for artifact_ref in artifact_refs]
        if page_size is not None:
            params.append(("page_size", str(page_size)))
        if page_token is not None:
            params.append(("page_token", str(page_token)))
        return f"{s8_url}/v1/audit-slice?" + parse.urlencode(params)

    tampered_root = "blake3:" + ("f" * 64)
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT leaf.sequence, leaf.artifact_id, leaf.root, checkpoint.root
                FROM s8.ledger_leaf AS leaf
                JOIN s8.merkle_checkpoint AS checkpoint
                  ON checkpoint.seq = leaf.sequence
                ORDER BY leaf.sequence DESC
                LIMIT 2;
                """
            )
            rows = cur.fetchall()
            if len(rows) < 2:
                raise AssertionError("at least two deployed audit leaves are required for paged tamper verification")
            rows = sorted(rows, key=lambda row: int(row[0]))
            page_artifact_refs = tuple(str(row[1]) for row in rows)
            target_row = rows[-1]
            sequence = int(target_row[0])
            artifact_ref = str(target_row[1])
            original_leaf_root = str(target_row[2])
            original_checkpoint_root = str(target_row[3])
            if original_leaf_root == tampered_root:
                tampered_root = "blake3:" + ("e" * 64)
            cur.execute("ALTER TABLE s8.ledger_leaf DISABLE TRIGGER ledger_leaf_append_only;")
            cur.execute("ALTER TABLE s8.merkle_checkpoint DISABLE TRIGGER merkle_checkpoint_append_only;")
            cur.execute("UPDATE s8.ledger_leaf SET root = %s WHERE sequence = %s;", (tampered_root, sequence))
            cur.execute("UPDATE s8.merkle_checkpoint SET root = %s WHERE seq = %s;", (tampered_root, sequence))
            cur.execute("ALTER TABLE s8.ledger_leaf ENABLE TRIGGER ledger_leaf_append_only;")
            cur.execute("ALTER TABLE s8.merkle_checkpoint ENABLE TRIGGER merkle_checkpoint_append_only;")

    try:
        tampered_audit = _get_json(
            audit_slice_url((artifact_ref,)),
            token=token,
        )
        verification = dict(tampered_audit["verification"])
        if verification.get("valid"):
            raise AssertionError(f"deployed audit verifier accepted tampered audit root: {verification}")
        paged_tampered_audit = _get_json(
            audit_slice_url(page_artifact_refs, page_size=1),
            token=token,
        )
        paged_verification = dict(paged_tampered_audit["verification"])
        if paged_verification.get("valid"):
            raise AssertionError(f"deployed paged audit verifier accepted tampered audit root: {paged_verification}")
        next_page_token = paged_tampered_audit.get("next_page_token")
        if next_page_token is None:
            raise AssertionError("deployed paged audit tamper check did not return a second page token")
        second_page_tampered_audit = _get_json(
            audit_slice_url(page_artifact_refs, page_size=1, page_token=int(next_page_token)),
            token=token,
        )
        second_page_verification = dict(second_page_tampered_audit["verification"])
        if second_page_verification.get("valid"):
            raise AssertionError(
                f"deployed second-page audit verifier accepted tampered audit root: {second_page_verification}"
            )
        return {
            "artifact_ref": artifact_ref,
            "break_sequence": verification.get("break_sequence"),
            "reason": verification.get("reason"),
            "paged_artifact_refs": list(page_artifact_refs),
            "paged_next_page_token": next_page_token,
            "paged_break_sequence": paged_verification.get("break_sequence"),
            "paged_reason": paged_verification.get("reason"),
            "paged_second_break_sequence": second_page_verification.get("break_sequence"),
            "paged_second_reason": second_page_verification.get("reason"),
        }
    finally:
        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("ALTER TABLE s8.ledger_leaf DISABLE TRIGGER ledger_leaf_append_only;")
                cur.execute("ALTER TABLE s8.merkle_checkpoint DISABLE TRIGGER merkle_checkpoint_append_only;")
                cur.execute(
                    "UPDATE s8.ledger_leaf SET root = %s WHERE sequence = %s;",
                    (original_leaf_root, sequence),
                )
                cur.execute(
                    "UPDATE s8.merkle_checkpoint SET root = %s WHERE seq = %s;",
                    (original_checkpoint_root, sequence),
                )
                cur.execute("ALTER TABLE s8.ledger_leaf ENABLE TRIGGER ledger_leaf_append_only;")
                cur.execute("ALTER TABLE s8.merkle_checkpoint ENABLE TRIGGER merkle_checkpoint_append_only;")


def _postgres_append_only_denials(dsn: str) -> dict[str, bool]:
    return {
        "append_only_update_denied": _postgres_statement_denied(
            dsn,
            """
            UPDATE s8.artifact_record
            SET kind = 'tampered'
            WHERE artifact_id = (
                SELECT artifact_id FROM s8.artifact_record ORDER BY merkle_seq LIMIT 1
            );
            """,
            "append-only table artifact_record",
        ),
        "append_only_truncate_denied": _postgres_statement_denied(
            dsn,
            "TRUNCATE s8.ledger_leaf;",
            "append-only table ledger_leaf",
        ),
        "writer_role_update_denied": _postgres_statement_denied(
            dsn,
            """
            SET ROLE argus_s8_ledger_writer;
            UPDATE s8.artifact_record
            SET kind = 'tampered'
            WHERE artifact_id = (
                SELECT artifact_id FROM s8.artifact_record ORDER BY merkle_seq LIMIT 1
            );
            """,
            "permission denied",
        ),
        "writer_role_truncate_denied": _postgres_statement_denied(
            dsn,
            """
            SET ROLE argus_s8_ledger_writer;
            TRUNCATE s8.ledger_leaf;
            """,
            "permission denied",
        ),
        "s10_quota_update_denied": _postgres_statement_denied(
            dsn,
            """
            UPDATE s10.quota_ledger_entry
            SET entry_type = 'consume'
            WHERE sequence = (
                SELECT sequence FROM s10.quota_ledger_entry ORDER BY sequence LIMIT 1
            );
            """,
            "append-only table quota_ledger_entry",
        ),
        "s10_quota_delete_denied": _postgres_statement_denied(
            dsn,
            """
            DELETE FROM s10.quota_ledger_entry
            WHERE sequence = (
                SELECT sequence FROM s10.quota_ledger_entry ORDER BY sequence LIMIT 1
            );
            """,
            "append-only table quota_ledger_entry",
        ),
        "s10_quota_truncate_denied": _postgres_statement_denied(
            dsn,
            "TRUNCATE s10.quota_ledger_entry;",
            "append-only table quota_ledger_entry",
        ),
    }


def _postgres_statement_denied(dsn: str, sql: str, expected_message: str) -> bool:
    import psycopg

    try:
        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(sql)
                conn.rollback()
                return False
    except Exception as exc:
        return expected_message in str(exc)


def _battery_d_tamper_detected(
    evidence: dict[str, Any],
    *,
    s8_url: str,
    token: str,
    health_token: str,
    minio_port: str,
    model_record: dict[str, Any],
    unrelated_ref: str,
) -> None:
    from minio import Minio

    payload_url = f"{s8_url}/v1/artifacts/{model_record['artifact_ref']}/payload"
    _get_json(payload_url, token=token)
    minio = Minio(
        f"127.0.0.1:{minio_port}",
        access_key="argus",
        secret_key="argus-dev-password",
        secure=False,
    )
    key = _minio_object_key(minio, "argus-s8-objects", model_record["content_hash"])
    tampered = b'{"tampered":true}'
    minio.put_object("argus-s8-objects", key, BytesIO(tampered), length=len(tampered), content_type="application/json")
    response = _get_json(payload_url, token=token, expected_status=404)
    if response["error"] != "HashMismatchError":
        raise AssertionError(f"unexpected tamper detection payload: {response}")
    tampered_record = _get_json(f"{s8_url}/v1/artifacts/{model_record['artifact_ref']}/record", token=token)
    unrelated = _get_json(f"{s8_url}/v1/artifacts/{unrelated_ref}/record", token=token)
    health = _get_json(f"{s8_url}/healthz", token=health_token)
    if tampered_record["artifact_ref"] != model_record["artifact_ref"]:
        raise AssertionError(f"tampered targeted record read returned wrong artifact: {tampered_record}")
    if unrelated["artifact_ref"] != unrelated_ref:
        raise AssertionError(f"unrelated targeted record read returned wrong artifact: {unrelated}")
    if int(health["record_count"]) < 2:
        raise AssertionError(f"unexpected S8 health record count after tamper: {health}")
    _record(
        evidence,
        "d",
        "tampered MinIO object bytes detected by S8 verify-on-read without breaking unrelated targeted reads",
        {
            "error": response["error"],
            "artifact_ref": model_record["artifact_ref"],
            "tampered_record_read_after_tamper": tampered_record["artifact_ref"],
            "tampered_record_size_bytes_after_tamper": tampered_record["size_bytes"],
            "unrelated_record_read_after_tamper": unrelated_ref,
            "health_record_count_after_tamper": health["record_count"],
        },
    )


def _minio_object_key(minio: Any, bucket: str, content_hash: str) -> str:
    object_name = content_hash.removeprefix("blake3:") if content_hash.startswith("blake3:") else content_hash.replace(":", "_")
    for item in minio.list_objects(bucket, recursive=True):
        if item.object_name and item.object_name.endswith("/" + object_name):
            return item.object_name
    raise KeyError(content_hash)


def _battery_e_budget_halt(
    evidence: dict[str, Any],
    s10_url: str,
    image: str,
    s8_url: str,
    *,
    token: str,
    read_token: str,
) -> None:
    budget_json = _post_json(
        f"{s10_url}/v1/budget-tokens",
        {},
        expected_status=201,
        token=token,
    )
    scope_json = _post_json(
        f"{s10_url}/v1/scope-tokens",
        {},
        expected_status=201,
        token=token,
    )
    launch_body = _launch_request_json(
        job_id="m0-budget-halt-job",
        image=image,
        budget=budget_json,
        scope=scope_json,
        args=("-c", "sleep 2"),
        env={},
        env_allowlist=(),
        wallclock_s=1,
    )
    response = _post_json(
        f"{s10_url}/v1/sandboxes:launch",
        launch_body,
        expected_status=403,
        token=token,
    )
    if response.get("error") != "BudgetExceededError":
        raise AssertionError(f"budget halt did not fail with BudgetExceededError: {response}")
    events = response.get("audit_events") or []
    if "budget.halt" not in events:
        raise AssertionError(f"budget halt event missing from deployed S10 response: {events}")
    handle = response.get("handle") or {}
    if handle.get("state") != "BUDGET_HALTED":
        raise AssertionError(f"budget halt response handle state was not BUDGET_HALTED: {response}")
    launch_provenance_ref = handle.get("launch_provenance_ref")
    if not isinstance(launch_provenance_ref, str) or not launch_provenance_ref:
        raise AssertionError("budget halt launch provenance missing")
    _get_json(f"{s8_url}/v1/artifacts/{launch_provenance_ref}/record", token=read_token)
    spend_final = _battery_spend_final(
        s8_url=s8_url,
        read_token=read_token,
        job_id="m0-budget-halt-job",
        launch_provenance_ref=launch_provenance_ref,
        expected_state="BUDGET_HALTED",
    )
    _record(
        evidence,
        "e",
        "sandbox ran past budget and was halted with audit and spend.final evidence",
        {
            "events": events,
            "launch_handle_state": handle["state"],
            "spend_final_ref": spend_final["artifact_ref"],
            "spend_final_state": spend_final["final_state"],
            "spend_final_cost_usd_exact": spend_final["cost_usd_exact"],
            "spend_final_meter_sample_count": spend_final["meter_sample_count"],
            "spend_final_meter_max_cadence_s": spend_final["meter_max_cadence_s"],
            "spend_final_meter_halted_by_meter": spend_final["meter_halted_by_meter"],
            "spend_final_meter_halt_latency_s": spend_final["meter_halt_latency_s"],
            "spend_final_meter_halt_completion_latency_s": spend_final["meter_halt_completion_latency_s"],
            "spend_final_meter_freeze_capture_latency_s": spend_final["meter_freeze_capture_latency_s"],
            "spend_final_meter_dcgm_available": spend_final["meter_dcgm_available"],
            "spend_final_meter_nvidia_smi_available": spend_final["meter_nvidia_smi_available"],
            "spend_final_meter_gpu_count": spend_final["meter_gpu_count"],
            "spend_final_meter_gpu_models": spend_final["meter_gpu_models"],
            "spend_final_meter_mig_enabled": spend_final["meter_mig_enabled"],
            "spend_final_meter_mig_instance_count": spend_final["meter_mig_instance_count"],
            "spend_final_meter_gpu_telemetry_source": spend_final["meter_gpu_telemetry_source"],
            "spend_final_meter_gap_sample_count": spend_final["meter_gap_sample_count"],
        },
    )


def _battery_partial_capture(
    evidence: dict[str, Any],
    s10_url: str,
    image: str,
    s8_url: str,
    *,
    token: str,
    read_token: str,
) -> None:
    budget_json = _post_json(
        f"{s10_url}/v1/budget-tokens",
        {},
        expected_status=201,
        token=token,
    )
    scope_json = _post_json(
        f"{s10_url}/v1/scope-tokens",
        {},
        expected_status=201,
        token=token,
    )
    launch_body = _launch_request_json(
        job_id="m0-partial-capture-job",
        image=image,
        budget=budget_json,
        scope=scope_json,
        args=("-c", "printf 'partial-before-halt\\n'; sleep 5"),
        env={},
        env_allowlist=(),
        wallclock_s=1,
    )
    response = _post_json(
        f"{s10_url}/v1/sandboxes:launch",
        launch_body,
        expected_status=201,
        token=token,
    )
    handle = response.get("handle") or {}
    if handle.get("state") != "TIMED_OUT" or response.get("timed_out") is not True:
        raise AssertionError(f"partial capture probe did not return a timed-out sandbox: {response}")
    stdout = str(response.get("stdout") or "")
    if "partial-before-halt" not in stdout:
        raise AssertionError(f"partial capture probe did not surface pre-halt stdout: {response}")
    events = response.get("audit_events") or []
    expected_order = ["sandbox.freeze", "sandbox.partial_result", "sandbox.terminate", "sandbox.timeout"]
    event_positions = [events.index(name) for name in expected_order if name in events]
    if len(event_positions) != len(expected_order) or event_positions != sorted(event_positions):
        raise AssertionError(f"partial capture audit events were missing or out of order: {events}")
    launch_provenance_ref = handle.get("launch_provenance_ref")
    if not isinstance(launch_provenance_ref, str) or not launch_provenance_ref:
        raise AssertionError(f"partial capture launch provenance missing: {response}")
    _get_json(f"{s8_url}/v1/artifacts/{launch_provenance_ref}/record", token=read_token)
    spend_final = _battery_spend_final(
        s8_url=s8_url,
        read_token=read_token,
        job_id="m0-partial-capture-job",
        launch_provenance_ref=launch_provenance_ref,
        expected_state="TIMED_OUT",
    )
    partial_ref = spend_final["partial_result_ref"]
    if not isinstance(partial_ref, str) or not partial_ref:
        raise AssertionError(f"partial capture spend.final did not carry partial_result_ref: {spend_final}")
    partial_payload = _get_json(f"{s8_url}/v1/artifacts/{partial_ref}/payload", token=read_token)
    if partial_payload.get("schema") != "argus.s10.partial_result.v1":
        raise AssertionError(f"unexpected partial result schema: {partial_payload}")
    if partial_payload.get("reason") != "wallclock_timeout":
        raise AssertionError(f"unexpected partial result reason: {partial_payload}")
    if "partial-before-halt" not in str(partial_payload.get("stdout") or ""):
        raise AssertionError(f"partial result did not preserve stdout: {partial_payload}")
    if partial_payload.get("captured_after_freeze") is not True:
        raise AssertionError(f"partial result was not captured after freeze: {partial_payload}")
    if partial_payload.get("freeze_succeeded") is not True or partial_payload.get("terminate_succeeded") is not True:
        raise AssertionError(f"partial result did not record freeze+terminate success: {partial_payload}")
    if partial_payload.get("frozen_state") != "FROZEN" or partial_payload.get("terminated_state") != "TERMINATED":
        raise AssertionError(f"partial result did not record FROZEN->TERMINATED contract states: {partial_payload}")
    if partial_payload.get("capture_error") is not None:
        raise AssertionError(f"partial result capture_error was not empty: {partial_payload}")
    if partial_payload.get("logs_truncated") is not False:
        raise AssertionError(f"partial result unexpectedly truncated normal probe logs: {partial_payload}")
    if int(partial_payload.get("log_capture_limit_bytes") or 0) < 65536:
        raise AssertionError(f"partial result log capture limit was missing or too low: {partial_payload}")
    _record(
        evidence,
        "partial-capture",
        "deployed S10 real Docker mid-flight halt froze the sandbox, captured partial stdout as C4, terminated, and linked spend.final lineage",
        {
            "events": events,
            "launch_handle_state": handle["state"],
            "launch_timed_out": response["timed_out"],
            "launch_stdout": stdout,
            "launch_provenance_ref": launch_provenance_ref,
            "partial_result_ref": partial_ref,
            "partial_result_reason": partial_payload["reason"],
            "partial_result_stdout_bytes": partial_payload["stdout_bytes"],
            "partial_result_log_capture_limit_bytes": partial_payload["log_capture_limit_bytes"],
            "partial_result_logs_truncated": partial_payload["logs_truncated"],
            "partial_result_captured_after_freeze": partial_payload["captured_after_freeze"],
            "partial_result_freeze_succeeded": partial_payload["freeze_succeeded"],
            "partial_result_terminate_succeeded": partial_payload["terminate_succeeded"],
            "partial_result_frozen_state": partial_payload["frozen_state"],
            "partial_result_terminated_state": partial_payload["terminated_state"],
            "spend_final_ref": spend_final["artifact_ref"],
            "spend_final_partial_result_captured": spend_final["partial_result_captured"],
            "spend_final_state": spend_final["final_state"],
            "spend_final_meter_sample_count": spend_final["meter_sample_count"],
            "spend_final_meter_halted_by_meter": spend_final["meter_halted_by_meter"],
            "spend_final_meter_halt_latency_s": spend_final["meter_halt_latency_s"],
            "spend_final_meter_halt_completion_latency_s": spend_final["meter_halt_completion_latency_s"],
            "spend_final_meter_freeze_capture_latency_s": spend_final["meter_freeze_capture_latency_s"],
        },
    )


def _nearest_rank_percentile(values: list[float], percentile: float) -> float:
    if not values:
        raise AssertionError("percentile requires at least one value")
    if percentile <= 0 or percentile > 100:
        raise AssertionError(f"percentile must be in (0, 100], got {percentile}")
    ordered = sorted(float(value) for value in values)
    rank = max(1, math.ceil(len(ordered) * percentile / 100.0))
    return ordered[rank - 1]


def _halt_latency_summary(
    latencies_s: list[float],
    *,
    expected_trials: int = HALT_LATENCY_TRIALS,
    limit_s: float = HALT_LATENCY_LIMIT_S,
) -> dict[str, Any]:
    if len(latencies_s) != expected_trials:
        raise AssertionError(f"expected {expected_trials} halt latency trials, got {len(latencies_s)}")
    if any(float(latency) < 0 for latency in latencies_s):
        raise AssertionError(f"halt latency cannot be negative: {latencies_s}")
    summary = {
        "trial_count": len(latencies_s),
        "limit_s": limit_s,
        "p50_nearest_rank_s": round(_nearest_rank_percentile(latencies_s, 50), 6),
        "p95_nearest_rank_s": round(_nearest_rank_percentile(latencies_s, 95), 6),
        "p99_nearest_rank_s": round(_nearest_rank_percentile(latencies_s, 99), 6),
        "max_s": round(max(latencies_s), 6),
    }
    if summary["p99_nearest_rank_s"] > limit_s:
        raise AssertionError(f"halt latency p99 exceeded {limit_s}s: {summary}")
    return summary


def _battery_halt_latency_trials(
    evidence: dict[str, Any],
    s10_url: str,
    image: str,
    s8_url: str,
    *,
    token: str,
    read_token: str,
    trials: int = HALT_LATENCY_TRIALS,
) -> None:
    latencies_s: list[float] = []
    freeze_capture_latencies_s: list[float] = []
    max_cadences_s: list[float] = []
    sample_counts: list[int] = []
    launch_refs: list[str] = []
    spend_refs: list[str] = []
    for trial in range(1, trials + 1):
        budget_json = _post_json(
            f"{s10_url}/v1/budget-tokens",
            {},
            expected_status=201,
            token=token,
        )
        scope_json = _post_json(
            f"{s10_url}/v1/scope-tokens",
            {},
            expected_status=201,
            token=token,
        )
        launch_body = _launch_request_json(
            job_id="m0-halt-latency-job",
            image=image,
            budget=budget_json,
            scope=scope_json,
            args=("-c", "sleep 2"),
            env={},
            env_allowlist=(),
            wallclock_s=1,
        )
        response = _post_json(
            f"{s10_url}/v1/sandboxes:launch",
            launch_body,
            expected_status=403,
            token=token,
        )
        if response.get("error") != "BudgetExceededError":
            raise AssertionError(f"halt latency trial {trial} did not fail with BudgetExceededError: {response}")
        events = response.get("audit_events") or []
        if "budget.halt" not in events or "spend.final" not in events:
            raise AssertionError(f"halt latency trial {trial} missing audit events: {events}")
        handle = response.get("handle") or {}
        if handle.get("state") != "BUDGET_HALTED":
            raise AssertionError(f"halt latency trial {trial} handle was not BUDGET_HALTED: {response}")
        launch_provenance_ref = handle.get("launch_provenance_ref")
        if not isinstance(launch_provenance_ref, str) or not launch_provenance_ref:
            raise AssertionError(f"halt latency trial {trial} launch provenance missing: {response}")
        _get_json(f"{s8_url}/v1/artifacts/{launch_provenance_ref}/record", token=read_token)
        spend_final = _battery_spend_final(
            s8_url=s8_url,
            read_token=read_token,
            job_id="m0-halt-latency-job",
            launch_provenance_ref=launch_provenance_ref,
            expected_state="BUDGET_HALTED",
            page_size=max(100, trials * 2),
        )
        latencies_s.append(spend_final["meter_halt_latency_s"])
        freeze_capture_latencies_s.append(spend_final["meter_freeze_capture_latency_s"])
        max_cadences_s.append(spend_final["meter_max_cadence_s"])
        sample_counts.append(spend_final["meter_sample_count"])
        launch_refs.append(launch_provenance_ref)
        spend_refs.append(spend_final["artifact_ref"])

    summary = _halt_latency_summary(latencies_s, expected_trials=trials)
    _record(
        evidence,
        "halt-latency-50",
        "deployed S10 real Docker budget halt p99 latency stayed within the 2s S10 bound over 50 trials",
        {
            **summary,
            "latencies_s": [round(latency, 6) for latency in latencies_s],
            "freeze_capture_latencies_s": [round(latency, 6) for latency in freeze_capture_latencies_s],
            "max_freeze_capture_latency_s": round(max(freeze_capture_latencies_s), 6),
            "max_cadence_s": round(max(max_cadences_s), 6),
            "min_meter_sample_count": min(sample_counts),
            "max_meter_sample_count": max(sample_counts),
            "launch_provenance_refs": launch_refs,
            "spend_final_refs": spend_refs,
        },
    )


def _recreate_s10_supervisor(
    *,
    docker: str,
    compose_file: str,
    env: dict[str, str],
    s10_url: str,
    health_token: str,
) -> dict[str, Any]:
    _run(
        [
            docker,
            "compose",
            "-f",
            compose_file,
            "up",
            "-d",
            "--no-deps",
            "--force-recreate",
            "--wait",
            "s10-supervisor",
        ],
        env=env,
        timeout=240,
    )
    _wait_health(f"{s10_url}/healthz", token=health_token)
    return _get_json(f"{s10_url}/healthz", token=health_token)


def _battery_non_injected_meter_gap(
    evidence: dict[str, Any],
    *,
    docker: str,
    compose_file: str,
    compose_env: dict[str, str],
    s10_url: str,
    s8_url: str,
    image: str,
    token: str,
    read_token: str,
    health_token: str,
) -> None:
    probe_env = {
        **compose_env,
        "ARGUS_S10_METER_INTERVAL_S": "0.1",
        "ARGUS_S10_METER_GAP_HALT_S": "0.1",
    }
    restored_interval_s = float(compose_env.get("ARGUS_S10_METER_INTERVAL_S", "1.0"))
    restored_gap_halt_s = float(compose_env.get("ARGUS_S10_METER_GAP_HALT_S", "5.0"))
    health: dict[str, Any] = {}
    try:
        health = _recreate_s10_supervisor(
            docker=docker,
            compose_file=compose_file,
            env=probe_env,
            s10_url=s10_url,
            health_token=health_token,
        )
        if health.get("resource_meter") != "docker-api-cgroup":
            raise AssertionError(f"S10 meter gap probe lost the Docker resource meter: {health}")
        if (
            abs(float(health.get("meter_interval_s", 999)) - 0.1) > 0.000001
            or abs(float(health.get("meter_gap_halt_s", 999)) - 0.1) > 0.000001
        ):
            raise AssertionError(f"S10 meter gap probe did not activate the low-gap cadence: {health}")

        budget_json = _post_json(
            f"{s10_url}/v1/budget-tokens",
            {},
            expected_status=201,
            token=token,
        )
        scope_json = _post_json(
            f"{s10_url}/v1/scope-tokens",
            {},
            expected_status=201,
            token=token,
        )
        launch_body = _launch_request_json(
            job_id="m0-meter-gap-job",
            image=image,
            budget=budget_json,
            scope=scope_json,
            args=("-c", "sleep 30"),
            env={},
            env_allowlist=(),
            wallclock_s=5,
        )
        response = _post_json(
            f"{s10_url}/v1/sandboxes:launch",
            launch_body,
            expected_status=201,
            token=token,
        )
        handle = response.get("handle") or {}
        if handle.get("state") != "TIMED_OUT" or response.get("timed_out") is not True:
            raise AssertionError(f"meter gap probe did not fail closed through a timed-out sandbox: {response}")
        stderr = str(response.get("stderr") or "")
        if "meter_gap" not in stderr:
            raise AssertionError(f"meter gap probe did not report meter_gap in stderr: {response}")
        launch_provenance_ref = handle.get("launch_provenance_ref")
        if not isinstance(launch_provenance_ref, str) or not launch_provenance_ref:
            raise AssertionError(f"meter gap probe launch provenance missing: {response}")
        _get_json(f"{s8_url}/v1/artifacts/{launch_provenance_ref}/record", token=read_token)
        spend_final = _battery_spend_final(
            s8_url=s8_url,
            read_token=read_token,
            job_id="m0-meter-gap-job",
            launch_provenance_ref=launch_provenance_ref,
            expected_state="TIMED_OUT",
        )
        if spend_final["meter_gap_sample_count"] < 1:
            raise AssertionError(f"meter gap probe spend.final had no non-injected gap sample: {spend_final}")
        if spend_final["meter_halted_by_meter"] is not True:
            raise AssertionError(f"meter gap probe spend.final was not halted by the meter: {spend_final}")
    finally:
        restored_health = _recreate_s10_supervisor(
            docker=docker,
            compose_file=compose_file,
            env=compose_env,
            s10_url=s10_url,
            health_token=health_token,
        )
        if abs(float(restored_health.get("meter_interval_s", 999)) - restored_interval_s) > 0.000001:
            raise AssertionError(f"S10 meter gap probe did not restore the default meter cadence: {restored_health}")
        if abs(float(restored_health.get("meter_gap_halt_s", 999)) - restored_gap_halt_s) > 0.000001:
            raise AssertionError(f"S10 meter gap probe did not restore the default meter gap threshold: {restored_health}")

    _record(
        evidence,
        "meter-gap",
        "deployed S10 real Docker meter-gap probe produced non-empty fail-closed spend.final evidence",
        {
            "s10_resource_meter": health["resource_meter"],
            "s10_meter_interval_s": health["meter_interval_s"],
            "s10_meter_gap_halt_s": health["meter_gap_halt_s"],
            "s10_meter_restored_interval_s": restored_health["meter_interval_s"],
            "s10_meter_restored_gap_halt_s": restored_health["meter_gap_halt_s"],
            "launch_handle_state": handle["state"],
            "launch_timed_out": response["timed_out"],
            "launch_stderr": stderr,
            "launch_provenance_ref": launch_provenance_ref,
            "spend_final_ref": spend_final["artifact_ref"],
            "spend_final_state": spend_final["final_state"],
            "spend_final_meter_sample_count": spend_final["meter_sample_count"],
            "spend_final_meter_gap_sample_count": spend_final["meter_gap_sample_count"],
            "spend_final_meter_gap_sources": spend_final["meter_gap_sources"],
            "spend_final_meter_gap_max_conservative_gap_s": spend_final["meter_gap_max_conservative_gap_s"],
            "spend_final_meter_halted_by_meter": spend_final["meter_halted_by_meter"],
            "spend_final_meter_max_cadence_s": spend_final["meter_max_cadence_s"],
            "spend_final_meter_dcgm_available": spend_final["meter_dcgm_available"],
            "spend_final_meter_nvidia_smi_available": spend_final["meter_nvidia_smi_available"],
            "spend_final_meter_gpu_count": spend_final["meter_gpu_count"],
            "spend_final_meter_gpu_models": spend_final["meter_gpu_models"],
            "spend_final_meter_mig_enabled": spend_final["meter_mig_enabled"],
            "spend_final_meter_mig_instance_count": spend_final["meter_mig_instance_count"],
            "spend_final_meter_gpu_telemetry_source": spend_final["meter_gpu_telemetry_source"],
        },
    )


def _battery_spend_final(
    *,
    s8_url: str,
    read_token: str,
    job_id: str,
    launch_provenance_ref: str,
    expected_state: str,
    page_size: int = 20,
) -> dict[str, Any]:
    query = _get_json(
        f"{s8_url}/v1/artifacts?kind=spend.final&job_id={parse.quote(job_id, safe='')}&page_size={page_size}",
        token=read_token,
    )
    matching_records = [
        record
        for record in query["records"]
        if launch_provenance_ref in (record.get("lineage", {}).get("input_refs") or [])
    ]
    if len(matching_records) != 1:
        raise AssertionError(f"expected one spend.final record for {job_id}, found {matching_records}")
    record = matching_records[0]
    payload = _get_json(f"{s8_url}/v1/artifacts/{record['artifact_ref']}/payload", token=read_token)
    input_refs = record.get("lineage", {}).get("input_refs") or []
    price_table = payload.get("price_table") or {}
    usage = payload.get("usage") or {}
    rollup = payload.get("usd_rollup") or {}
    metering = payload.get("metering") or {}
    meter_samples = metering.get("samples") or []
    partial_result_ref = payload.get("partial_result_ref")
    partial_result_captured = bool(payload.get("partial_result_captured"))
    if partial_result_ref:
        if not isinstance(partial_result_ref, str):
            raise AssertionError(f"spend.final partial_result_ref must be a string: {payload}")
        if partial_result_captured is not True:
            raise AssertionError(f"spend.final partial_result_captured was false despite ref: {payload}")
        if partial_result_ref not in input_refs:
            raise AssertionError(f"spend.final lineage did not include partial_result_ref: {record}")
    elif partial_result_captured:
        raise AssertionError(f"spend.final claimed partial capture without a ref: {payload}")
    if not isinstance(meter_samples, list):
        raise AssertionError(f"spend.final metering samples must be a list: {payload}")
    meter_gap_samples = [
        sample
        for sample in meter_samples
        if isinstance(sample, dict)
        and (
            sample.get("source") == "docker-api-cgroup-gap"
            or float(sample.get("conservative_gap_s") or 0) > 0
            or "meter_gap" in (sample.get("breached_dimensions") or [])
        )
    ]
    for sample in meter_gap_samples:
        dimensions = sample.get("breached_dimensions") or []
        if "meter_gap" not in dimensions or sample.get("halted") is not True:
            raise AssertionError(f"meter gap sample must fail closed with meter_gap dimension: {payload}")
    meter_gap_sources = sorted({str(sample.get("source") or "") for sample in meter_gap_samples})
    meter_gap_max_conservative_gap_s = max(
        (float(sample.get("conservative_gap_s") or 0) for sample in meter_gap_samples),
        default=0.0,
    )
    meter_breached_dimensions = sorted(
        {
            str(dimension)
            for sample in meter_samples
            if isinstance(sample, dict)
            for dimension in (sample.get("breached_dimensions") or [])
        }
    )
    if payload.get("schema") != "argus.s10.spend.final.v1":
        raise AssertionError(f"unexpected spend.final schema: {payload}")
    if payload.get("final_state") != expected_state:
        raise AssertionError(f"unexpected spend.final state: {payload}")
    if price_table.get("price_table_version") != "0.1.0":
        raise AssertionError(f"spend.final missing signed price table version: {payload}")
    if price_table.get("signer_key_id") != "argus-m0-price-table":
        raise AssertionError(f"spend.final missing price table signer: {payload}")
    if not str(price_table.get("signature", "")).startswith("hmac-sha256:"):
        raise AssertionError(f"spend.final price table signature missing: {payload}")
    if rollup.get("source") != "signed_price_table":
        raise AssertionError(f"spend.final did not use signed price table source: {payload}")
    expected_cost = (
        Decimal(str(usage.get("compute_units", 0))) * Decimal(str(price_table["usd_per_cpu_second"]))
        + Decimal(str(usage.get("gpu_seconds", 0)))
        * Decimal(str((price_table.get("usd_per_gpu_second") or {}).get("default", "0")))
        + Decimal(str(usage.get("model_tokens", 0)))
        / Decimal("1000")
        * Decimal(str((price_table.get("usd_per_1k_model_tokens") or {}).get("default", "0")))
    )
    expected_cost_exact = _decimal_wire(expected_cost)
    if rollup.get("cost_usd_exact") != expected_cost_exact:
        raise AssertionError(
            f"spend.final USD roll-up mismatch: expected={expected_cost_exact} payload={payload}"
        )
    if usage.get("cost_usd") != rollup.get("cost_usd"):
        raise AssertionError(f"spend.final usage cost did not match roll-up float view: {payload}")
    if int(metering.get("sample_count") or 0) < 1:
        raise AssertionError(f"spend.final missing resource-meter samples: {payload}")
    if float(metering.get("max_cadence_s") or 0) > 5:
        raise AssertionError(f"spend.final resource-meter cadence exceeded S10 bound: {payload}")
    if metering.get("dcgm_available") is not False:
        raise AssertionError(f"spend.final M0 no-GPU metering must report dcgm_available=false: {payload}")
    if metering.get("nvidia_smi_available") is not False:
        raise AssertionError(f"spend.final M0 no-GPU metering must report nvidia_smi_available=false: {payload}")
    if int(metering.get("gpu_count") or 0) != 0:
        raise AssertionError(f"spend.final M0 no-GPU metering must report gpu_count=0: {payload}")
    if metering.get("mig_enabled") is not False:
        raise AssertionError(f"spend.final M0 no-GPU metering must report mig_enabled=false: {payload}")
    if int(metering.get("mig_instance_count") or 0) != 0:
        raise AssertionError(f"spend.final M0 no-GPU metering must report mig_instance_count=0: {payload}")
    if expected_state == "BUDGET_HALTED":
        if metering.get("halted_by_meter") is not True:
            raise AssertionError(f"spend.final budget halt missing meter halt evidence: {payload}")
        if "halt_latency_s" not in metering:
            raise AssertionError(f"spend.final budget halt missing halt latency: {payload}")
        if float(metering["halt_latency_s"]) > 2:
            raise AssertionError(f"spend.final budget halt latency exceeded S10 bound: {payload}")
        if "freeze_capture_latency_s" not in metering:
            raise AssertionError(f"spend.final budget halt missing freeze/capture latency: {payload}")
        if float(metering["freeze_capture_latency_s"]) > 2:
            raise AssertionError(f"spend.final freeze/capture latency exceeded S10 bound: {payload}")
    return {
        "artifact_ref": record["artifact_ref"],
        "final_state": payload["final_state"],
        "price_table_version": price_table["price_table_version"],
        "cost_usd_exact": expected_cost_exact,
        "meter_sample_count": int(metering["sample_count"]),
        "meter_max_cadence_s": float(metering["max_cadence_s"]),
        "meter_halted_by_meter": bool(metering["halted_by_meter"]),
        "meter_halt_latency_s": float(metering["halt_latency_s"]),
        "meter_halt_detection_elapsed_s": float(metering.get("halt_detection_elapsed_s", 0)),
        "meter_halt_completion_elapsed_s": float(metering.get("halt_completion_elapsed_s", 0)),
        "meter_halt_completion_latency_s": float(metering.get("halt_completion_latency_s", 0)),
        "meter_freeze_capture_latency_s": float(metering.get("freeze_capture_latency_s", 0)),
        "meter_dcgm_available": bool(metering["dcgm_available"]),
        "meter_nvidia_smi_available": bool(metering["nvidia_smi_available"]),
        "meter_gpu_count": int(metering["gpu_count"]),
        "meter_gpu_models": list(metering.get("gpu_models") or []),
        "meter_mig_enabled": bool(metering["mig_enabled"]),
        "meter_mig_instance_count": int(metering["mig_instance_count"]),
        "meter_gpu_telemetry_source": str(metering.get("gpu_telemetry_source") or "unavailable"),
        "meter_breached_dimensions": meter_breached_dimensions,
        "meter_gap_sample_count": len(meter_gap_samples),
        "meter_gap_sources": meter_gap_sources,
        "meter_gap_max_conservative_gap_s": meter_gap_max_conservative_gap_s,
        "partial_result_ref": partial_result_ref,
        "partial_result_captured": partial_result_captured,
    }


def _battery_g_argusverify(evidence: dict[str, Any]) -> None:
    trust_store = InMemoryVerifierTrustStore()
    trust_store.register_key("m0-verifier", b"m0-verifier-secret")
    report = {
        "report_id": "vr-m0-spine",
        "claim_tier": "validated",
        "aggregate": {"passed": True},
        "checks": [{"id": "stub", "passed": True}],
    }
    signed = C3ReportSigner(key_id="m0-verifier", secret=b"m0-verifier-secret").sign(report)
    valid = verify_report(signed, trust_store)
    tampered = json.loads(json.dumps(signed))
    tampered["aggregate"]["passed"] = False
    invalid = verify_report(tampered, trust_store)
    if not valid.valid or invalid.valid:
        raise AssertionError("argusverify signature validation/tamper rejection failed")
    _record(
        evidence,
        "g",
        "argusverify accepted signed report and rejected tampered signature",
        {"valid_key_id": valid.key_id, "tampered_reason": invalid.reason},
    )


def _m0_validation_report(*, claim_tier: str, aggregate_passed: bool = True) -> dict[str, Any]:
    return {
        "report_id": "vr-m0-spine",
        "profile_ref": "c4://profile/m0-spine/v1",
        "frozen_pipeline_ref": "c4://pipeline/m0-spine/baseline",
        "checks": [
            {"check": "INJECTION", "status": "PASS"},
            {"check": "LEAKAGE", "status": "PASS"},
            {"check": "CROSS_CODE", "status": "PASS"},
        ],
        "aggregate": {
            "passed": aggregate_passed,
            "score": 0.98 if aggregate_passed else 0.0,
        },
        "claim_tier": claim_tier,
        "claim_tier_is_candidate": claim_tier == "novel-needs-human",
        "signature": {
            "algorithm": "placeholder",
            "key_id": "placeholder",
            "value": "placeholder",
        },
        "perturbation_pairs": [
            {"perturbation_id": "must-react-1", "kind": "must_react", "verdict": "pass"},
            {"perturbation_id": "must-not-react-1", "kind": "must_not_react", "verdict": "pass"},
        ],
        "insensitivity_flags": [],
        "challenger_panel": {"challenger_ids": ["challenger-a", "challenger-b"], "min_required": 2},
        "independence_attestation_debate": {
            "min_independent_challengers": 2,
            "lineage_disjoint": True,
            "correlation_warning": False,
        },
        "referee": {
            "referee_id": "s3-referee",
            "non_gameable": True,
            "signed_by": M0_C3_VERIFIER_KEY_ID,
            "distinct_from_proponent": True,
        },
        "debate_ref": "c4://debate/m0-spine/example",
    }


def _battery_signed_policy_service(evidence: dict[str, Any], *, policy_signing_key: bytes) -> None:
    service = _policy_service(policy_signing_key)
    signed = service.active_bundle
    tampered = replace(
        signed,
        resource_ceilings=replace(signed.resource_ceilings, cpu_m=signed.resource_ceilings.cpu_m + 1),
    )
    unknown_signer = replace(signed, signer_key_id="unknown-policy-signer")

    tamper_rejected = False
    unknown_rejected = False
    try:
        InMemoryPolicyService(
            initial_bundle=tampered,
            trust_store=InMemoryPolicyBundleTrustStore({signed.signer_key_id: policy_signing_key}),
        )
    except PolicyBundleSignatureError:
        tamper_rejected = True
    try:
        InMemoryPolicyService(
            initial_bundle=unknown_signer,
            trust_store=InMemoryPolicyBundleTrustStore({signed.signer_key_id: policy_signing_key}),
        )
    except PolicyBundleSignatureError:
        unknown_rejected = True
    if not signed.signature.startswith("hmac-sha256:") or not tamper_rejected or not unknown_rejected:
        raise AssertionError("signed S10 policy service did not fail closed")
    _record(
        evidence,
        "policy-signature",
        "S10 Docker launch policy bundle is signed and verified before activation",
        {
            "bundle_version": signed.bundle_version,
            "signer_key_id": signed.signer_key_id,
            "tamper_rejected": tamper_rejected,
            "unknown_signer_rejected": unknown_rejected,
        },
    )


def _battery_runtime_class_hint_policy(
    evidence: dict[str, Any],
    *,
    signing_key: bytes,
    policy_signing_key: bytes,
) -> None:
    tokens = InMemoryTokenService(signing_key=signing_key)
    service = _policy_service(
        policy_signing_key,
        risk_to_runtime={"standard": "docker", "high": "firecracker"},
    )
    matching = service.decide(
        _policy_hint_request(tokens, risk_class="standard", runtime_class_hint="docker")
    )
    unknown = service.decide(
        _policy_hint_request(tokens, risk_class="standard", runtime_class_hint="runc")
    )
    downgrade = service.decide(
        _policy_hint_request(tokens, risk_class="high", runtime_class_hint="docker")
    )
    if not matching.allowed or unknown.deny_reason != "runtime_class_hint_mismatch":
        raise AssertionError(f"runtime_class_hint unknown-value guard failed: {matching=}, {unknown=}")
    if downgrade.deny_reason != "runtime_class_hint_mismatch":
        raise AssertionError(f"runtime_class_hint downgrade guard failed: {downgrade=}")
    _record(
        evidence,
        "policy-hint",
        "runtime_class_hint cannot override the signed policy risk-to-runtime mapping",
        {
            "matching_hint_runtime": matching.runtime_class,
            "unknown_hint_deny_reason": unknown.deny_reason,
            "high_risk_downgrade_deny_reason": downgrade.deny_reason,
        },
    )


def _policy_hint_request(
    tokens: InMemoryTokenService,
    *,
    risk_class: str,
    runtime_class_hint: str,
) -> LaunchRequest:
    budget = tokens.mint_budget(
        caps=BudgetCaps(max_compute_units=10, max_wallclock_s=10, max_cost_usd=1),
        job_id=f"m0-policy-hint-{risk_class}",
        root_request_id=f"m0-policy-hint-{risk_class}-root",
        risk_class=risk_class,
    )
    scope = tokens.mint_scope(
        job_id=f"m0-policy-hint-{risk_class}",
        scopes=ScopeGrant(sandbox_risk_class=risk_class),
    )
    return LaunchRequest(
        job_id=f"m0-policy-hint-{risk_class}",
        subagent_id="m0-policy-hint",
        trace_id=f"trace-policy-hint-{risk_class}",
        budget_token=budget,
        scope_token=scope,
        image=DEFAULT_IMAGE,
        entrypoint=("sh",),
        args=("-c", "true"),
        env={},
        env_allowlist=(),
        requested_envelope=LaunchEnvelope(
            cpu_m=100,
            mem_bytes=16 * 1024 * 1024,
            gpu_count=0,
            wallclock_s=1,
            scratch_bytes=1024 * 1024,
            pids=16,
            estimated_cost_usd=0,
        ),
        runtime_class_hint=runtime_class_hint,
    )


def _launch_request_json(
    *,
    job_id: str,
    image: str,
    budget: dict[str, Any],
    scope: dict[str, Any],
    args: tuple[str, ...],
    env: dict[str, str],
    env_allowlist: tuple[str, ...],
    wallclock_s: int,
) -> dict[str, Any]:
    return {
        "job_id": job_id,
        "subagent_id": "m0-subagent",
        "trace_id": f"trace-{uuid4()}",
        "budget_token": budget,
        "scope_token": scope,
        "image": image,
        "entrypoint": ["sh"],
        "args": list(args),
        "env": env,
        "env_allowlist": list(env_allowlist),
        "requested_envelope": {
            "cpu_m": 1000,
            "mem_bytes": 32 * 1024 * 1024,
            "gpu_count": 0,
            "wallclock_s": wallclock_s,
            "scratch_bytes": 1024 * 1024,
            "pids": 16,
            "estimated_cost_usd": 0,
        },
        "runtime_class_hint": "auto",
        "policy_pin": None,
    }


def _run_no_network_launch(
    *,
    image: str,
    budget: dict[str, Any],
    scope: dict[str, Any],
    s10_url: str,
    token: str,
    s8_url: str,
    read_token: str,
) -> dict[str, Any]:
    launch = _launch_request_json(
        job_id="m0-spine-job",
        image=image,
        budget=budget,
        scope=scope,
        args=(
            "-c",
            "cat /proc/net/route; "
            "if grep -qE '^[^[:space:]]+[[:space:]]+00000000[[:space:]]' /proc/net/route; "
            "then echo default-route-found; exit 42; fi; "
            "echo no-default-route; echo ARGUS_UID=$(id -u)",
        ),
        env={"VISIBLE": "ok", "HIDDEN": "no"},
        env_allowlist=("VISIBLE",),
        wallclock_s=5,
    )
    result = _post_json(
        f"{s10_url}/v1/sandboxes:launch",
        launch,
        expected_status=201,
        token=token,
    )
    handle = result["handle"]
    stdout = str(result.get("stdout", ""))
    if result.get("exit_code") != 0 or "no-default-route" not in stdout or "HIDDEN" in stdout:
        raise AssertionError(f"no-network sandbox launch failed: exit={result.get('exit_code')} stdout={stdout!r}")
    if handle.get("state") != "SUCCEEDED":
        raise AssertionError(f"no-network launch response handle state was not SUCCEEDED: {result}")
    if not handle.get("launch_provenance_ref"):
        raise AssertionError("launch provenance ref missing")
    payload = _get_json(f"{s8_url}/v1/artifacts/{handle['launch_provenance_ref']}/payload", token=read_token)
    return {
        "stdout": stdout,
        "launch_provenance_ref": handle["launch_provenance_ref"],
        "exec_environment_digest": payload["exec_environment_digest"],
        "audit_events": result.get("audit_events", ()),
        "state": handle["state"],
        "runtime_class": handle["runtime_class"],
    }


def _policy_bundle() -> PolicyBundle:
    return PolicyBundle(
        bundle_version="argus-m0-battery",
        egress_allowlist=(),
        resource_ceilings=ResourceCeilings(
            cpu_m=1000,
            mem_bytes=64 * 1024 * 1024,
            gpu_count=0,
            wallclock_s=10,
            max_cost_usd=5,
        ),
        risk_to_runtime={"standard": "docker"},
        seccomp_profile_hash="blake3:" + "0" * 64,
        signer_key_id="",
        signature="",
    )


def _policy_service(
    policy_signing_key: bytes,
    *,
    risk_to_runtime: dict[str, str] | None = None,
) -> InMemoryPolicyService:
    signer_key_id = "argus-m0-battery-policy"
    bundle = _policy_bundle()
    if risk_to_runtime is not None:
        bundle = replace(bundle, risk_to_runtime=risk_to_runtime)
    signed = PolicyBundleSigner(key_id=signer_key_id, secret=policy_signing_key).sign(bundle)
    return InMemoryPolicyService(
        initial_bundle=signed,
        trust_store=InMemoryPolicyBundleTrustStore({signer_key_id: policy_signing_key}),
    )


def _post_json(
    url: str,
    body: dict[str, Any],
    *,
    expected_status: int,
    token: str | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 10,
) -> dict[str, Any]:
    encoded = json.dumps(body, sort_keys=True).encode("utf-8")
    request_headers = {"Content-Type": "application/json", **_auth_headers(token), **(headers or {})}
    req = request.Request(url, data=encoded, method="POST", headers=request_headers)
    return _open_json(req, expected_status=expected_status, timeout=timeout)


def _get_json(
    url: str,
    *,
    token: str | None = None,
    expected_status: int = 200,
    timeout: float = 10,
) -> dict[str, Any]:
    return _open_json(
        request.Request(url, method="GET", headers=_auth_headers(token)),
        expected_status=expected_status,
        timeout=timeout,
    )


def _auth_headers(token: str | None) -> dict[str, str]:
    if token is None:
        return {}
    return {"Authorization": f"Bearer {token}"}


def _artifact_record_from_json(value: dict[str, Any]) -> ArtifactRecord:
    producer = Producer(**dict(value["producer"]))
    lineage_body = dict(value["lineage"])
    lineage_body["input_refs"] = tuple(lineage_body.get("input_refs") or ())
    lineage_body["seeds"] = tuple(lineage_body.get("seeds") or ())
    lineage = Lineage(**lineage_body)
    return ArtifactRecord(
        artifact_ref=value["artifact_ref"],
        kind=value["kind"],
        content_hash=value["content_hash"],
        size_bytes=int(value["size_bytes"]),
        producer=producer,
        lineage=lineage,
        claim_tier=value.get("claim_tier", "ran-toy"),
        validation_report_ref=value.get("validation_report_ref"),
        created_at=value.get("created_at", ""),
    )


def _open_json(req: request.Request, *, expected_status: int, timeout: float = 10) -> dict[str, Any]:
    try:
        with request.urlopen(req, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
            status = response.status
    except error.HTTPError as exc:
        payload = json.loads(exc.read().decode("utf-8"))
        status = exc.code
    if status != expected_status:
        raise AssertionError(f"{req.full_url} returned {status}, expected {expected_status}: {payload}")
    return payload


def _wait_health(url: str, *, token: str, timeout_s: int = 60) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            payload = _get_json(url, token=token)
            if payload.get("status") == "ok":
                return
        except Exception:
            time.sleep(1)
    raise TimeoutError(f"health check did not pass: {url}")


def _ensure_image(docker: str, image: str) -> None:
    inspected = subprocess.run([docker, "image", "inspect", image], capture_output=True, text=True)
    if inspected.returncode == 0:
        return
    _run([docker, "pull", image], timeout=120)


def _run(
    command: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: int = 60,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        timeout=timeout,
        check=False,
        capture_output=True,
        text=True,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(
            "command failed: "
            + " ".join(command)
            + f"\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed


def _record(evidence: dict[str, Any], item_id: str, summary: str, detail: Any | None = None) -> None:
    entry: dict[str, Any] = {"item": item_id, "status": "pass", "summary": summary}
    if detail is not None:
        entry["detail"] = detail
    evidence["results"].append(entry)


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _git_head() -> str:
    completed = _run(["git", "rev-parse", "HEAD"], timeout=10)
    return completed.stdout.strip()


def _git_dirty() -> bool:
    completed = _run(["git", "status", "--porcelain"], timeout=10)
    return bool(completed.stdout.strip())


if __name__ == "__main__":
    raise SystemExit(main())
