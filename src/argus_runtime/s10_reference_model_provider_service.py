"""Deployable Anthropic-compatible reference model provider for S10-TC16."""

from __future__ import annotations

from hashlib import sha256
import hmac
import os
import re
import threading
from typing import Any, Mapping

from .http_json import JsonHttpApp, JsonRequest, serve_json_app


REFERENCE_MODEL_COUNT_ROUTE = "/v1/messages/count_tokens"
REFERENCE_MODEL_COMPLETE_ROUTE = "/v1/messages"
_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_]+|[^\w\s]", re.UNICODE)
_REFERENCE_COMPLETION = (
    "Brokered completion accepted. Token metering and provenance are enforced before this response is released."
)


class ReferenceModelProviderApp:
    """Small real HTTP provider used to exercise the complete model-broker boundary."""

    def __init__(
        self,
        *,
        model_id: str,
        credential_header: str,
        credential: str,
    ) -> None:
        if not model_id:
            raise ValueError("reference model_id is required")
        if not credential_header or any(char in credential_header for char in "\r\n:"):
            raise ValueError("reference model credential header is invalid")
        if not credential or any(char in credential for char in "\r\n"):
            raise ValueError("reference model credential is required")
        self.model_id = model_id
        self._credential_header = credential_header.lower()
        self._credential = credential
        self._counts_lock = threading.Lock()
        self._count_request_count = 0
        self._completion_request_count = 0
        self.http = JsonHttpApp()
        self._register_routes()

    @property
    def count_request_count(self) -> int:
        with self._counts_lock:
            return self._count_request_count

    @property
    def completion_request_count(self) -> int:
        with self._counts_lock:
            return self._completion_request_count

    def _register_routes(self) -> None:
        @self.http.route("GET", "/healthz")
        def health(request: JsonRequest) -> tuple[int, Any]:
            del request
            return 200, {
                "service": "s10-reference-model-provider",
                "status": "ok",
                "model_id": self.model_id,
                "count_requests": self.count_request_count,
                "completion_requests": self.completion_request_count,
            }

        @self.http.route("POST", REFERENCE_MODEL_COUNT_ROUTE)
        def count_tokens(request: JsonRequest) -> tuple[int, Any]:
            denied = self._authorize(request)
            if denied is not None:
                return denied
            try:
                body = _validated_model_request(
                    request.body,
                    expected_model_id=self.model_id,
                    require_max_tokens=False,
                )
                input_tokens = _count_input_tokens(body)
            except ValueError as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}
            with self._counts_lock:
                self._count_request_count += 1
            return 200, {"input_tokens": input_tokens}

        @self.http.route("POST", REFERENCE_MODEL_COMPLETE_ROUTE)
        def complete(request: JsonRequest) -> tuple[int, Any]:
            denied = self._authorize(request)
            if denied is not None:
                return denied
            try:
                body = _validated_model_request(request.body, expected_model_id=self.model_id)
                input_tokens = _count_input_tokens(body)
                max_tokens = _positive_int(body.get("max_tokens"), "max_tokens")
                response_text, output_tokens = _bounded_reference_completion(max_tokens)
            except ValueError as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}
            with self._counts_lock:
                self._completion_request_count += 1
                request_seq = self._completion_request_count
            request_hash = sha256(_input_text(body).encode("utf-8")).hexdigest()[:16]
            return 200, {
                "id": f"msg_argus_{request_hash}_{request_seq}",
                "type": "message",
                "role": "assistant",
                "model": self.model_id,
                "content": [{"type": "text", "text": response_text}],
                "stop_reason": "end_turn" if output_tokens < max_tokens else "max_tokens",
                "stop_sequence": None,
                "usage": {
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                },
            }

    def _authorize(self, request: JsonRequest) -> tuple[int, dict[str, str]] | None:
        supplied = request.headers.get(self._credential_header, "")
        if not supplied or not hmac.compare_digest(supplied, self._credential):
            return 403, {"error": "broker_credential_required"}
        return None


def main() -> None:
    host = os.environ.get("ARGUS_S10_REFERENCE_MODEL_HOST", "127.0.0.1")
    port = int(os.environ.get("ARGUS_S10_REFERENCE_MODEL_PORT", "8080"))
    model_id = os.environ.get("ARGUS_S10_REFERENCE_MODEL_ID", "argus-reference-model-v1")
    credential_header = os.environ.get(
        "ARGUS_S10_REFERENCE_MODEL_CREDENTIAL_HEADER",
        "X-Argus-Model-Credential",
    )
    credential = os.environ.get("ARGUS_S10_REFERENCE_MODEL_BROKER_CREDENTIAL", "")
    serve_json_app(
        ReferenceModelProviderApp(
            model_id=model_id,
            credential_header=credential_header,
            credential=credential,
        ).http,
        host=host,
        port=port,
    )


def _validated_model_request(
    value: Any,
    *,
    expected_model_id: str,
    require_max_tokens: bool = True,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("model request must be an object")
    body = dict(value)
    if body.get("model") != expected_model_id:
        raise ValueError("model request does not match the configured reference model")
    if require_max_tokens:
        _positive_int(body.get("max_tokens"), "max_tokens")
    if body.get("stream") is not None and body.get("stream") is not False:
        raise ValueError("streaming is not supported by the reference provider")
    messages = body.get("messages")
    if not isinstance(messages, list) or not messages:
        raise ValueError("messages must be a non-empty array")
    for message in messages:
        if not isinstance(message, Mapping) or message.get("role") not in {"user", "assistant"}:
            raise ValueError("each message requires a user or assistant role")
        _content_text(message.get("content"))
    if "system" in body:
        _content_text(body["system"])
    return body


def _count_input_tokens(body: Mapping[str, Any]) -> int:
    return max(len(_TOKEN_PATTERN.findall(_input_text(body))), 1)


def _input_text(body: Mapping[str, Any]) -> str:
    parts: list[str] = []
    if "system" in body:
        parts.append(_content_text(body["system"]))
    for message in body.get("messages", []):
        parts.append(str(message["role"]))
        parts.append(_content_text(message["content"]))
    return "\n".join(parts)


def _content_text(value: Any) -> str:
    if isinstance(value, str) and value:
        return value
    if isinstance(value, list) and value:
        parts: list[str] = []
        for block in value:
            if not isinstance(block, Mapping) or block.get("type") != "text":
                raise ValueError("reference provider supports text content blocks only")
            text = block.get("text")
            if not isinstance(text, str) or not text:
                raise ValueError("text content blocks require non-empty text")
            parts.append(text)
        return "\n".join(parts)
    raise ValueError("message content must be non-empty text")


def _bounded_reference_completion(max_tokens: int) -> tuple[str, int]:
    tokens = _TOKEN_PATTERN.findall(_REFERENCE_COMPLETION)
    bounded = tokens[:max_tokens]
    text = " ".join(bounded)
    return text, len(bounded)


def _positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{field} must be a positive integer")
    return value


if __name__ == "__main__":
    main()
