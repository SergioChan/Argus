from __future__ import annotations

import argparse
import importlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
from types import ModuleType
from typing import Any, Sequence, TextIO

from jsonschema import Draft202012Validator

from argus_core import (
    C3ReportSigner,
    C3ReportVerifier,
    CheckResult,
    InMemoryArtifactStore,
    InMemoryVerifierTrustStore,
    InMemoryRegistry,
    JobEnvelope,
    LifecycleEvent,
    LifecycleState,
    Lineage,
    Producer,
    S1ConformanceAttestationAuthority,
    S1ReferenceConformanceHarness,
    S3Verifier,
    Subagent,
    SubagentDescriptor,
    SubagentRuntime,
    SubagentSDKRunner,
    build_s1_capability_descriptor,
    hash_json,
    parse_job_envelope,
    publish_s1_capability_descriptor,
)


ROOT = Path(__file__).resolve().parents[2]
C5_SCHEMA_PATH = ROOT / "schemas" / "contracts" / "c5.capability-descriptor.schema.json"
CODEGEN_SCRIPT = ROOT / "scripts" / "generate_bindings.py"
CLI_FREEZE_CODE_REF = "argus-core:s1.cli.freeze"
CLI_FREEZE_ENVIRONMENT_DIGEST = "python:argus-subagent-cli:v1"


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr
    parser = _build_parser()
    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return int(exc.code or 0)

    try:
        return int(args.func(args, out, err))
    except CliUsageError as exc:
        print(str(exc), file=err)
        return 2
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}", file=err)
        return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="argus-subagent")
    subcommands = parser.add_subparsers(dest="command", required=True)

    init_parser = subcommands.add_parser("init", help="scaffold a local S1 subagent project")
    init_parser.add_argument("name")
    init_parser.add_argument("--out", default=".")
    init_parser.set_defaults(func=_cmd_init)

    validate_parser = subcommands.add_parser("validate-descriptor", help="validate an S1 descriptor as C5")
    validate_parser.add_argument("--descriptor", required=True)
    validate_parser.set_defaults(func=_cmd_validate_descriptor)

    run_parser = subcommands.add_parser("run", help="run a local S1 lifecycle")
    run_parser.add_argument("--subagent", required=True, help="module.path:ClassName or /path/subagent.py:ClassName")
    run_parser.add_argument("--job", required=True)
    run_parser.add_argument("--output")
    run_parser.set_defaults(func=_cmd_run)

    conformance_parser = subcommands.add_parser("conformance", help="run the S1 reference conformance harness")
    conformance_parser.add_argument("--subagent", required=True)
    conformance_parser.add_argument("--job", required=True)
    conformance_parser.add_argument("--level", choices=("bronze", "silver", "gold"), required=True)
    conformance_parser.add_argument("--conformance-expires-at")
    conformance_parser.add_argument("--output")
    conformance_parser.add_argument("--descriptor-output")
    conformance_parser.add_argument("--attestation-key-id", default="s1-reference-conformance-key-v1")
    conformance_parser.add_argument("--attestation-private-key-hex")
    conformance_parser.add_argument("--independence-tag", action="append", default=())
    conformance_parser.set_defaults(func=_cmd_conformance)

    replay_parser = subcommands.add_parser("replay", help="replay lifecycle events from a run output")
    replay_parser.add_argument("--run-output", required=True)
    replay_parser.add_argument("--job-id", required=True)
    replay_parser.set_defaults(func=_cmd_replay)

    codegen_parser = subcommands.add_parser("codegen", help="run deterministic C1 binding codegen")
    codegen_mode = codegen_parser.add_mutually_exclusive_group(required=True)
    codegen_mode.add_argument("--check", action="store_true")
    codegen_mode.add_argument("--write", action="store_true")
    codegen_parser.set_defaults(func=_cmd_codegen)

    freeze_parser = subcommands.add_parser("freeze", help="freeze a local S1 build result")
    freeze_parser.add_argument("--job-id", required=True)
    freeze_parser.add_argument("--build", required=True)
    freeze_parser.add_argument("--output")
    freeze_parser.set_defaults(func=_cmd_freeze)

    return parser


def _cmd_init(args: argparse.Namespace, stdout: TextIO, _stderr: TextIO) -> int:
    slug = _slug(args.name)
    class_name = _class_name(slug)
    root = Path(args.out) / slug
    tests_dir = root / "tests"
    tests_dir.mkdir(parents=True, exist_ok=True)
    (root / "subagent.py").write_text(_subagent_template(class_name, slug), encoding="utf-8")
    _write_json(
        root / "descriptor.json",
        {
            "subagent_id": slug,
            "contract_version": "1.0.0",
            "subtopics": ["ewpt"],
            "required_adapters": [],
            "revision": 1,
            "independence_tags": [],
        },
    )
    _write_json(
        root / "job.json",
        {
            "job_id": f"{slug}-local-job",
            "envelope_version": "1.0.0",
            "subtopic": "ewpt",
            "required_adapters": [],
            "allowed_adapters": [],
            "verifier_profile_ref": "c4://profile/ewpt/local",
            "estimated_cost": 0.1,
            "budget_cost": 1.0,
        },
    )
    (root / "pyproject.toml").write_text(
        "\n".join(
            [
                "[project]",
                f'name = "{slug}"',
                'version = "0.1.0"',
                'requires-python = ">=3.11"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    (tests_dir / "test_subagent_smoke.py").write_text(_smoke_test_template(class_name), encoding="utf-8")
    _dump({"status": "created", "path": str(root), "class": class_name}, stdout)
    return 0


def _cmd_validate_descriptor(args: argparse.Namespace, stdout: TextIO, _stderr: TextIO) -> int:
    descriptor_payload = _read_json(Path(args.descriptor))
    descriptor, options = _descriptor_from_payload(descriptor_payload)
    c5_descriptor = build_s1_capability_descriptor(descriptor, **options)
    c5_payload = c5_descriptor.as_c5_payload()
    _validate_c5_payload(c5_payload)
    _dump({"status": "valid", "c1_descriptor": descriptor_payload, "c5_descriptor": c5_payload}, stdout)
    return 0


def _cmd_run(args: argparse.Namespace, stdout: TextIO, _stderr: TextIO) -> int:
    subagent = _load_subagent(args.subagent)
    envelope = parse_job_envelope(_read_json(Path(args.job)))
    local_validator = _LocalValidationClient()
    artifact_store = InMemoryArtifactStore(report_verifier=local_validator.report_verifier)
    runtime = SubagentRuntime(descriptor=subagent.descriptor, artifact_store=artifact_store)
    runner = SubagentSDKRunner(subagent, runtime=runtime)

    acceptance = runner.accept(envelope, root_request_id=f"cli:{envelope.job_id}", trace_id=f"trace:cli:{envelope.job_id}")
    if not acceptance.accepted:
        result = {
            "schema": "argus.s1.cli_run_result.v1",
            "status": "rejected",
            "job_id": envelope.job_id,
            "current_state": runtime.store.current(envelope.job_id).state.value,
            "acceptance": acceptance.as_c1_payload(),
            "events": [_event_payload(event) for event in runtime.store.events(envelope.job_id)],
            "ledger_refs": list(runtime.store.ledger_refs(envelope.job_id)),
        }
        _emit_result(result, stdout=stdout, output_path=args.output)
        return 1

    plan = runner.plan(envelope, root_request_id=f"cli:{envelope.job_id}", trace_id=f"trace:cli:{envelope.job_id}")
    build = runner.build(
        envelope.job_id,
        plan.payload,
        root_request_id=f"cli:{envelope.job_id}",
        trace_id=f"trace:cli:{envelope.job_id}",
    )
    validated = runner.validate(
        envelope.job_id,
        build.payload,
        profile_ref=str(envelope.verifier_profile_ref),
        blind_dataset_handle=f"blind://argus-subagent/{envelope.job_id}",
        budget_token_ref=f"budget://argus-subagent/{envelope.job_id}",
        validation_client=local_validator,
        report_verifier=local_validator.report_verifier,
        root_request_id=f"cli:{envelope.job_id}",
        trace_id=f"trace:cli:{envelope.job_id}",
    )
    report_payload = validated.payload["subagent_report"]
    report = runner.report(
        envelope.job_id,
        report_payload,
        root_request_id=f"cli:{envelope.job_id}",
        trace_id=f"trace:cli:{envelope.job_id}",
    )
    result = {
        "schema": "argus.s1.cli_run_result.v1",
        "status": "reported",
        "job_id": envelope.job_id,
        "current_state": runtime.store.current(envelope.job_id).state.value,
        "acceptance": acceptance.as_c1_payload(),
        "plan": plan.payload,
        "build_result": build.payload,
        "validation": validated.payload,
        "report": report.payload,
        "events": [_event_payload(event) for event in runtime.store.events(envelope.job_id)],
        "ledger_refs": list(runtime.store.ledger_refs(envelope.job_id)),
    }
    _emit_result(result, stdout=stdout, output_path=args.output)
    return 0


def _cmd_conformance(args: argparse.Namespace, stdout: TextIO, _stderr: TextIO) -> int:
    subagent = _load_subagent(args.subagent)
    envelope = parse_job_envelope(_read_json(Path(args.job)))
    artifact_store = InMemoryArtifactStore()
    capability_descriptor = build_s1_capability_descriptor(
        subagent.descriptor,
        revision=1,
        independence_tags=tuple(args.independence_tag or ()),
    )
    authority = _load_s1_conformance_attestation_authority(args)
    harness = S1ReferenceConformanceHarness(
        attestation_signer=authority.signer if authority is not None else None
    )
    result = harness.run(
        subagent,
        envelope=envelope,
        level=args.level,
        artifact_store=artifact_store,
        capability_descriptor=capability_descriptor,
    )
    payload = result.as_payload()
    if args.conformance_expires_at is not None:
        payload["descriptor_conformance"] = result.descriptor_conformance_block(expires_at=args.conformance_expires_at)
    if args.descriptor_output:
        if args.conformance_expires_at is None:
            raise CliUsageError("--descriptor-output requires --conformance-expires-at")
        if authority is None:
            raise CliUsageError("--descriptor-output requires --attestation-private-key-hex")
        registry = InMemoryRegistry(
            artifact_store=artifact_store,
            conformance_attestation_verifier=authority.verifier,
        )
        published = publish_s1_capability_descriptor(
            registry,
            subagent.descriptor,
            revision=1,
            independence_tags=tuple(args.independence_tag or ()),
            conformance_result=result,
            conformance_expires_at=args.conformance_expires_at,
        )
        _write_json(Path(args.descriptor_output), published.as_c5_payload())
    _emit_result(payload, stdout=stdout, output_path=args.output)
    return 0 if result.aggregate_passed else 1


def _load_s1_conformance_attestation_authority(
    args: argparse.Namespace,
) -> S1ConformanceAttestationAuthority | None:
    if args.attestation_private_key_hex is None:
        return None
    try:
        private_key = bytes.fromhex(args.attestation_private_key_hex)
    except ValueError as exc:
        raise CliUsageError("--attestation-private-key-hex must be 32 raw bytes encoded as hex") from exc
    if len(private_key) != 32:
        raise CliUsageError("--attestation-private-key-hex must be 32 raw bytes encoded as hex")
    return S1ConformanceAttestationAuthority.from_private_key_bytes(
        key_id=args.attestation_key_id,
        private_key_bytes=private_key,
    )


def _cmd_replay(args: argparse.Namespace, stdout: TextIO, _stderr: TextIO) -> int:
    run_output = _read_json(Path(args.run_output))
    events = tuple(_event_from_payload(event) for event in run_output.get("events", ()))
    current = _reduce_events(events, job_id=args.job_id)
    result = {
        "schema": "argus.s1.cli_replay_result.v1",
        "job_id": args.job_id,
        "current_state": current.state.value,
        "last_sequence": current.last_sequence,
        "event_count": len(events),
        "trajectory": [_event_payload(event) for event in events],
    }
    _dump(result, stdout)
    return 0


def _cmd_codegen(args: argparse.Namespace, stdout: TextIO, stderr: TextIO) -> int:
    mode = "--check" if args.check else "--write"
    completed = subprocess.run(
        [sys.executable, str(CODEGEN_SCRIPT), mode],
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.stdout:
        print(completed.stdout, end="", file=stdout)
    if completed.stderr:
        print(completed.stderr, end="", file=stderr)
    return int(completed.returncode)


def _cmd_freeze(args: argparse.Namespace, stdout: TextIO, _stderr: TextIO) -> int:
    build_payload = _read_json(Path(args.build))
    frozen = _freeze_build_result(job_id=args.job_id, build_payload=build_payload)
    _emit_result(frozen, stdout=stdout, output_path=args.output)
    return 0


class CliUsageError(ValueError):
    pass


def _load_subagent(ref: str) -> Subagent:
    module_ref, separator, class_name = ref.rpartition(":")
    if not separator or not module_ref or not class_name:
        raise CliUsageError("--subagent must be module.path:ClassName or /path/subagent.py:ClassName")
    module = _load_module(module_ref)
    candidate = getattr(module, class_name, None)
    if not isinstance(candidate, type) or not issubclass(candidate, Subagent):
        raise CliUsageError(f"{class_name} is not an argus_core.Subagent subclass")
    try:
        instance = candidate()
    except TypeError as exc:
        raise CliUsageError(f"{class_name} must be constructible without arguments for local CLI runs") from exc
    if not isinstance(instance, Subagent):
        raise CliUsageError(f"{class_name} did not construct an S1 Subagent")
    return instance


def _load_module(module_ref: str) -> ModuleType:
    path = Path(module_ref)
    if path.exists() or module_ref.endswith(".py"):
        if not path.exists():
            raise CliUsageError(f"subagent module file not found: {module_ref}")
        module_name = "argus_subagent_cli_" + re.sub(r"[^A-Za-z0-9_]", "_", path.stem)
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise CliUsageError(f"cannot import subagent module file: {module_ref}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module
    return importlib.import_module(module_ref)


def _descriptor_from_payload(payload: dict[str, Any]) -> tuple[SubagentDescriptor, dict[str, Any]]:
    descriptor = SubagentDescriptor(
        subagent_id=_required_str(payload, "subagent_id"),
        contract_version=_required_str(payload, "contract_version"),
        subtopics=tuple(_required_str_list(payload, "subtopics")),
        required_adapters=tuple(str(item) for item in payload.get("required_adapters", ())),
    )
    options: dict[str, Any] = {
        "revision": _required_int(payload, "revision"),
        "independence_tags": tuple(str(item) for item in payload.get("independence_tags", ())),
        "trust_class": str(payload.get("trust_class", "internal")),
    }
    if "capability_scopes" in payload:
        options["capability_scopes"] = tuple(str(item) for item in payload["capability_scopes"])
    if "provenance_ref" in payload:
        options["provenance_ref"] = str(payload["provenance_ref"])
    if "conformance" in payload:
        conformance = payload["conformance"]
        if not isinstance(conformance, dict):
            raise CliUsageError("conformance must be an object")
        options["conformance"] = {str(key): str(value) for key, value in conformance.items()}
    return descriptor, options


def _required_str(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise CliUsageError(f"descriptor missing required field: {key}")
    return value


def _required_int(payload: dict[str, Any], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int):
        raise CliUsageError(f"descriptor missing required field: {key}")
    return value


def _required_str_list(payload: dict[str, Any], key: str) -> list[str]:
    value = payload.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise CliUsageError(f"descriptor missing required field: {key}")
    return value


def _validate_c5_payload(payload: dict[str, Any]) -> None:
    schema = _read_json(C5_SCHEMA_PATH)
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(payload), key=lambda error: list(error.path))
    if errors:
        raise CliUsageError("; ".join(error.message for error in errors))


class _LocalValidationClient:
    def __init__(self) -> None:
        self._key_id = "argus-subagent-local-s3"
        self._secret = b"argus-subagent-local-s3-secret"
        trust_store = InMemoryVerifierTrustStore()
        trust_store.register_key(self._key_id, self._secret)
        self.report_verifier = C3ReportVerifier(trust_store)
        self._s3 = S3Verifier(
            verifier_id="argus-subagent-local-verifier",
            signer_key_id=self._key_id,
            signer=C3ReportSigner(key_id=self._key_id, secret=self._secret),
        )

    def validate(self, request: dict[str, Any]) -> dict[str, Any]:
        return self._s3.build_report(
            profile_ref=str(request["profile_ref"]),
            frozen_pipeline_ref=str(request["frozen_pipeline_ref"]),
            proponent_id="argus-subagent-local-run",
            checks=(CheckResult("INJECTION", "INCONCLUSIVE", {"reason": "local CLI run does not claim verifier pass"}),),
            challenger_ids=(),
            debate_ref="c4://debate/local-cli-not-run",
        )


def _freeze_build_result(*, job_id: str, build_payload: dict[str, Any]) -> dict[str, Any]:
    artifact_refs = build_payload.get("artifact_refs")
    if not isinstance(artifact_refs, list) or not artifact_refs or not all(isinstance(ref, str) and ref for ref in artifact_refs):
        raise CliUsageError("freeze requires build_result.artifact_refs")
    payload = {
        "schema": "argus.s1.frozen_pipeline.v1",
        "entrypoint": "predict",
        "entrypoint_contract_version": "argus.s3.frozen_pipeline_entrypoint.v1",
        "job_id": job_id,
        "artifact_refs": list(artifact_refs),
        "build_result_hash": hash_json(build_payload),
        "diagnostics_hash": hash_json(build_payload.get("diagnostics", {})),
        "uncertainty_summary": build_payload.get("uncertainty_summary", {"representation": "none"}),
    }
    store = InMemoryArtifactStore()
    record = store.create_artifact(
        kind="frozen_pipeline",
        payload=payload,
        producer=Producer(subsystem="S1", version="0.0.0", actor_id="s1.cli.freeze", job_id=job_id),
        lineage=Lineage(
            input_refs=tuple(artifact_refs),
            code_ref=CLI_FREEZE_CODE_REF,
            environment_digest=CLI_FREEZE_ENVIRONMENT_DIGEST,
            job_id=job_id,
        ),
    )
    return {
        "schema": "argus.s1.cli_freeze_result.v1",
        "job_id": job_id,
        "frozen_pipeline_ref": record.artifact_ref,
        "payload": payload,
        "record": {
            "kind": record.kind,
            "content_hash": record.content_hash,
            "producer": {
                "subsystem": record.producer.subsystem,
                "version": record.producer.version,
                "actor_id": record.producer.actor_id,
                "job_id": record.producer.job_id,
            },
            "lineage": {
                "input_refs": list(record.lineage.input_refs),
                "code_ref": record.lineage.code_ref,
                "environment_digest": record.lineage.environment_digest,
                "seeds": list(record.lineage.seeds),
                "actor_id": record.lineage.actor_id,
                "job_id": record.lineage.job_id,
                "contamination_index_version": record.lineage.contamination_index_version,
            },
        },
    }


def _reduce_events(events: tuple[LifecycleEvent, ...], *, job_id: str):
    from argus_core import reduce_lifecycle

    return reduce_lifecycle(events, job_id=job_id)


def _event_payload(event: LifecycleEvent) -> dict[str, Any]:
    return {
        "event_id": event.event_id,
        "job_id": event.job_id,
        "sequence": event.sequence,
        "from_state": event.from_state.value,
        "to_state": event.to_state.value,
        "method": event.method,
        "trigger": event.trigger,
        "payload_hash": event.payload_hash,
        "idempotency_key": event.idempotency_key,
        "root_request_id": event.root_request_id,
        "trace_id": event.trace_id,
        "ledger_ref": event.ledger_ref,
    }


def _event_from_payload(payload: Any) -> LifecycleEvent:
    if not isinstance(payload, dict):
        raise CliUsageError("replay events must be objects")
    return LifecycleEvent(
        job_id=str(payload["job_id"]),
        sequence=int(payload["sequence"]),
        from_state=LifecycleState(str(payload["from_state"])),
        to_state=LifecycleState(str(payload["to_state"])),
        method=str(payload["method"]),
        trigger=str(payload.get("trigger", "")),
        payload_hash=str(payload["payload_hash"]),
        idempotency_key=str(payload["idempotency_key"]),
        root_request_id=str(payload.get("root_request_id") or payload["job_id"]),
        trace_id=str(payload.get("trace_id") or f"trace:{payload['job_id']}"),
        event_id=str(payload["event_id"]),
        ledger_ref=payload.get("ledger_ref"),
    )


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CliUsageError(f"file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise CliUsageError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise CliUsageError(f"{path} must contain a JSON object")
    return payload


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _dump(payload: dict[str, Any], stdout: TextIO) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True), file=stdout)


def _emit_result(payload: dict[str, Any], *, stdout: TextIO, output_path: str | None) -> None:
    if output_path:
        _write_json(Path(output_path), payload)
    else:
        _dump(payload, stdout)


def _slug(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
    if not slug:
        raise CliUsageError("name must contain at least one alphanumeric character")
    return slug


def _class_name(slug: str) -> str:
    return "".join(part[:1].upper() + part[1:] for part in slug.split("-")) + "Subagent"


def _subagent_template(class_name: str, slug: str) -> str:
    return f'''from __future__ import annotations

from argus_core import ExecContext, JobEnvelope, Lineage, Subagent, SubagentDescriptor


class {class_name}(Subagent):
    def __init__(self) -> None:
        super().__init__(
            SubagentDescriptor(
                subagent_id="{slug}",
                contract_version="1.0.0",
                subtopics=("ewpt",),
                required_adapters=(),
            )
        )

    def plan(self, ctx: ExecContext, envelope: JobEnvelope) -> dict[str, object]:
        return {{
            "steps": [{{"step_id": "fit", "kind": "train", "description": "Fit a local EWPT baseline"}}],
            "adapters_required": list(envelope.required_adapters),
            "datasets_required": [],
            "risk_notes": [],
        }}

    def build(self, ctx: ExecContext, plan: dict[str, object]) -> dict[str, object]:
        job_id = str(plan["job_id"])
        artifact = ctx.emit_artifact(
            {{"schema": "argus.s1.scaffold_model.v1", "job_id": job_id, "plan_hash": plan["plan_hash"]}},
            kind="model",
            lineage=Lineage(
                input_refs=(),
                code_ref="git:{slug}:local-build",
                environment_digest="python:{slug}:local",
                seeds=("{slug}-seed-v1",),
                job_id=job_id,
            ),
        )
        return {{
            "artifact_refs": [str(artifact["artifact_ref"])],
            "diagnostics": {{"model_ref": str(artifact["artifact_ref"])}},
            "self_checks": [{{"type": "smoke", "status": "PASS", "advisory": True}}],
        }}
'''


def _smoke_test_template(class_name: str) -> str:
    return f'''from __future__ import annotations

from subagent import {class_name}


def test_subagent_descriptor() -> None:
    subagent = {class_name}()
    assert subagent.descriptor.contract_version == "1.0.0"
    assert "ewpt" in subagent.descriptor.subtopics
'''


if __name__ == "__main__":
    raise SystemExit(main())
