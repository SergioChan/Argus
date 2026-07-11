"""Run a self-contained S2 frozen inference payload inside an S10 sandbox."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Mapping

from argus_core.canonical import canonical_json_bytes
from argus_core.s2 import FrozenPipelineRunner, PipelineFreezeError


ENTRYPOINT_REQUEST_SCHEMA = "argus.s3.frozen_pipeline_entrypoint_request.v1"
ENTRYPOINT_OUTPUT_SCHEMA = "argus.s3.frozen_pipeline_execution_output.v1"
FORBIDDEN_LABEL_FIELDS = frozenset(
    {
        "answers",
        "blind_answers",
        "blind_labels",
        "ground_truth",
        "labels",
        "targets",
        "truth",
    }
)


class FrozenPipelineEntrypointError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def execute_frozen_pipeline(
    *,
    entrypoint_request: Mapping[str, Any],
    frozen_pipeline: Mapping[str, Any],
    inputs: Mapping[str, Any],
) -> dict[str, Any]:
    request = _mapping(entrypoint_request, "entrypoint request", "S3_FROZEN_PIPELINE_ENTRYPOINT_REQUEST_INVALID")
    pipeline = _mapping(frozen_pipeline, "frozen pipeline", "S3_FROZEN_PIPELINE_EXECUTION_PAYLOAD_INVALID")
    normalized_inputs = _mapping(inputs, "execution inputs", "S3_FROZEN_PIPELINE_EXECUTION_INPUTS_INVALID")
    _assert_request(request)
    _assert_no_label_material(normalized_inputs)

    try:
        prediction = FrozenPipelineRunner(artifact_store=None).predict_payload(
            pipeline,
            normalized_inputs,
            loaded_from_c4=True,
        )
    except PipelineFreezeError as exc:
        raise FrozenPipelineEntrypointError(
            "S3_FROZEN_PIPELINE_EXECUTION_FAILED",
            "frozen pipeline execution failed validation",
        ) from exc

    verification_request = _mapping(
        request.get("verification_request"),
        "verification request",
        "S3_FROZEN_PIPELINE_ENTRYPOINT_REQUEST_INVALID",
    )
    entrypoint = _mapping(
        request.get("entrypoint"),
        "entrypoint",
        "S3_FROZEN_PIPELINE_ENTRYPOINT_REQUEST_INVALID",
    )
    frozen_pipeline_ref = _required_string(
        verification_request.get("frozen_pipeline_ref"),
        "S3_FROZEN_PIPELINE_ENTRYPOINT_REQUEST_INVALID",
    )
    if entrypoint.get("frozen_pipeline_ref") != frozen_pipeline_ref:
        raise FrozenPipelineEntrypointError(
            "S3_FROZEN_PIPELINE_ENTRYPOINT_REF_MISMATCH",
            "entrypoint does not bind the verification frozen pipeline",
        )
    content_hash = _required_string(
        entrypoint.get("content_hash"),
        "S3_FROZEN_PIPELINE_ENTRYPOINT_REQUEST_INVALID",
    )
    return {
        "schema": ENTRYPOINT_OUTPUT_SCHEMA,
        "frozen_pipeline_ref": frozen_pipeline_ref,
        "frozen_pipeline_content_hash": content_hash,
        "entrypoint": "predict",
        "outputs_units_tagged": prediction.outputs_units_tagged,
        "uncertainty": prediction.uncertainty,
        "io_signature": prediction.io_signature,
        "diagnostics": prediction.diagnostics,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--entrypoint-request-json", required=True)
    parser.add_argument("--frozen-pipeline-json", required=True)
    parser.add_argument("--inputs-json", required=True)
    args = parser.parse_args(argv)
    try:
        output = execute_frozen_pipeline(
            entrypoint_request=_json_object(args.entrypoint_request_json, "S3_FROZEN_PIPELINE_ENTRYPOINT_REQUEST_INVALID"),
            frozen_pipeline=_json_object(args.frozen_pipeline_json, "S3_FROZEN_PIPELINE_EXECUTION_PAYLOAD_INVALID"),
            inputs=_json_object(args.inputs_json, "S3_FROZEN_PIPELINE_EXECUTION_INPUTS_INVALID"),
        )
    except FrozenPipelineEntrypointError as exc:
        sys.stderr.write(f"{exc.code}: {exc.message}\n")
        return 2
    sys.stdout.write(canonical_json_bytes(output).decode("utf-8") + "\n")
    return 0


def _json_object(raw: str, code: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise FrozenPipelineEntrypointError(code, "argument is not valid JSON") from exc
    return _mapping(value, "argument", code)


def _mapping(value: Any, context: str, code: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise FrozenPipelineEntrypointError(code, f"{context} must be a JSON object")
    return {str(key): item for key, item in value.items()}


def _assert_request(request: Mapping[str, Any]) -> None:
    if request.get("schema") != ENTRYPOINT_REQUEST_SCHEMA:
        raise FrozenPipelineEntrypointError(
            "S3_FROZEN_PIPELINE_ENTRYPOINT_REQUEST_INVALID",
            "entrypoint request schema is unsupported",
        )
    entrypoint = _mapping(
        request.get("entrypoint"),
        "entrypoint",
        "S3_FROZEN_PIPELINE_ENTRYPOINT_REQUEST_INVALID",
    )
    if entrypoint.get("method") != "predict":
        raise FrozenPipelineEntrypointError(
            "S3_FROZEN_PIPELINE_ENTRYPOINT_METHOD_INVALID",
            "entrypoint method must be predict",
        )
    verification_request = _mapping(
        request.get("verification_request"),
        "verification request",
        "S3_FROZEN_PIPELINE_ENTRYPOINT_REQUEST_INVALID",
    )
    _required_string(
        verification_request.get("frozen_pipeline_ref"),
        "S3_FROZEN_PIPELINE_ENTRYPOINT_REQUEST_INVALID",
    )


def _assert_no_label_material(value: Any) -> None:
    if _contains_label_material(value):
        raise FrozenPipelineEntrypointError(
            "S3_FROZEN_PIPELINE_EXECUTION_INPUT_LABEL_MATERIAL_FORBIDDEN",
            "execution inputs contain forbidden label material",
        )


def _contains_label_material(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str) and key.lower() in FORBIDDEN_LABEL_FIELDS:
                return True
            if _contains_label_material(item):
                return True
        return False
    if isinstance(value, list | tuple):
        return any(_contains_label_material(item) for item in value)
    return False


def _required_string(value: Any, code: str) -> str:
    if not isinstance(value, str) or not value:
        raise FrozenPipelineEntrypointError(code, "required identifier is missing")
    return value


if __name__ == "__main__":
    raise SystemExit(main())
