"""Command line entrypoint for S2 build explainability workflows."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence, TextIO

from argus_core import (
    ExplainabilityReportRequest,
    ExplainabilityReporter,
    InMemoryArtifactStore,
    Lineage,
    Producer,
)


class S2CliUsageError(Exception):
    """Raised for user-correctable argus-s2 CLI errors."""


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
    except S2CliUsageError as exc:
        print(str(exc), file=err)
        return 2
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}", file=err)
        return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="argus-s2")
    subcommands = parser.add_subparsers(dest="command", required=True)

    explain = subcommands.add_parser("explain", help="generate an S2 explainability report from C4 artifacts")
    explain.add_argument("--store", required=True, help="Path to a C4 artifact bundle JSON file")
    explain.add_argument("--build", required=True, help="C4 frozen_pipeline artifact ref to explain")
    explain.add_argument("--out", help="Optional path for the report payload JSON")
    explain.add_argument("--format", choices=("json", "text"), default="text")
    explain.set_defaults(func=_cmd_explain)

    return parser


def _cmd_explain(args: argparse.Namespace, stdout: TextIO, _stderr: TextIO) -> int:
    store = load_artifact_bundle(Path(args.store))
    result = ExplainabilityReporter(artifact_store=store).explain(ExplainabilityReportRequest(build_ref=args.build))
    report_payload = _payload(store, result.report_ref)
    if args.out:
        output_path = Path(args.out)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary = {
        "status": result.status,
        "build_ref": result.build_ref,
        "report_ref": result.report_ref,
        "sections": list(result.sections),
        "output": args.out,
    }
    if args.format == "json":
        print(json.dumps(summary, sort_keys=True), file=stdout)
    else:
        print(f"{result.status} {result.report_ref}", file=stdout)
        print("sections: " + ", ".join(result.sections), file=stdout)
        if args.out:
            print(f"written: {args.out}", file=stdout)
    return 0


def load_artifact_bundle(path: Path) -> InMemoryArtifactStore:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise S2CliUsageError(f"cannot read artifact bundle: {path}") from exc
    if not isinstance(payload, Mapping):
        raise S2CliUsageError("artifact bundle must be a JSON object")
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list):
        raise S2CliUsageError("artifact bundle requires an artifacts array")
    store = InMemoryArtifactStore()
    for item in artifacts:
        if not isinstance(item, Mapping):
            raise S2CliUsageError("artifact bundle entries must be objects")
        record_payload = item.get("record")
        artifact_payload = item.get("payload")
        if not isinstance(record_payload, Mapping):
            raise S2CliUsageError("artifact bundle entries require record objects")
        store.create_artifact(
            kind=_string(record_payload, "kind"),
            payload=artifact_payload,
            producer=_producer(record_payload.get("producer")),
            lineage=_lineage(record_payload.get("lineage")),
            artifact_ref=_string(record_payload, "artifact_ref"),
            claim_tier=str(record_payload.get("claim_tier") or "ran-toy"),
            validation_report_ref=_optional_string(record_payload.get("validation_report_ref")),
            created_at=_optional_string(record_payload.get("created_at")),
        )
    return store


def dump_artifact_bundle(store: InMemoryArtifactStore) -> dict[str, object]:
    artifacts = []
    for record in store.query_artifacts():
        artifacts.append(
            {
                "record": {
                    "artifact_ref": record.artifact_ref,
                    "kind": record.kind,
                    "producer": asdict(record.producer),
                    "lineage": asdict(record.lineage),
                    "claim_tier": record.claim_tier,
                    "validation_report_ref": record.validation_report_ref,
                    "created_at": record.created_at,
                },
                "payload": _payload(store, record.artifact_ref),
            }
        )
    return {"artifacts": artifacts}


def _payload(store: InMemoryArtifactStore, artifact_ref: str) -> dict[str, Any]:
    payload = json.loads(store.get_artifact(artifact_ref).decode("utf-8"))
    if not isinstance(payload, dict):
        raise S2CliUsageError(f"artifact payload is not an object: {artifact_ref}")
    return payload


def _producer(value: Any) -> Producer:
    if not isinstance(value, Mapping):
        raise S2CliUsageError("artifact record producer must be an object")
    return Producer(
        subsystem=_string(value, "subsystem"),
        version=_string(value, "version"),
        actor_id=_optional_string(value.get("actor_id")),
        job_id=_optional_string(value.get("job_id")),
    )


def _lineage(value: Any) -> Lineage:
    if not isinstance(value, Mapping):
        raise S2CliUsageError("artifact record lineage must be an object")
    input_refs = value.get("input_refs")
    seeds = value.get("seeds", ())
    if not isinstance(input_refs, (list, tuple)):
        raise S2CliUsageError("artifact record lineage.input_refs must be a list")
    if not isinstance(seeds, (list, tuple)):
        raise S2CliUsageError("artifact record lineage.seeds must be a list")
    return Lineage(
        input_refs=tuple(str(ref) for ref in input_refs),
        code_ref=_string(value, "code_ref"),
        environment_digest=_string(value, "environment_digest"),
        seeds=tuple(str(seed) for seed in seeds),
        actor_id=_optional_string(value.get("actor_id")),
        job_id=_optional_string(value.get("job_id")),
        contamination_index_version=_optional_string(value.get("contamination_index_version")),
    )


def _string(value: Mapping[str, Any], key: str) -> str:
    raw = value.get(key)
    if not isinstance(raw, str) or not raw.strip():
        raise S2CliUsageError(f"artifact record missing string field: {key}")
    return raw.strip()


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise S2CliUsageError("optional artifact record field must be a string when present")
    value = value.strip()
    return value or None


if __name__ == "__main__":
    raise SystemExit(main())
