"""Fail-closed S10/S8 artifact access for the M1 reference runtime."""

from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
import json
from typing import Any, Mapping, Sequence
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

from argus_core import (
    ArtifactQueryFilter,
    ArtifactQueryPage,
    ArtifactRecord,
    Lineage,
    LineageEdge,
    LineageGraph,
    Producer,
    canonical_json_bytes,
)


DEFAULT_RUNTIME_TOKEN_TTL_S = 600


class RuntimeArtifactStoreError(RuntimeError):
    """Raised when the M1 runtime cannot prove a brokered C4 operation succeeded."""


@dataclass(frozen=True)
class RuntimeIdentitySession:
    """A server-policy-bound runtime identity and its scoped S10 access."""

    s10_url: str
    access_token: str
    caller_id: str
    job_id: str
    timeout_s: float = 10.0

    @classmethod
    def from_bootstrap(
        cls,
        *,
        s10_url: str,
        bootstrap_token: str,
        caller_id: str,
        expected_job_id: str,
        ttl_s: int = DEFAULT_RUNTIME_TOKEN_TTL_S,
        timeout_s: float = 10.0,
    ) -> "RuntimeIdentitySession":
        if not bootstrap_token:
            raise RuntimeArtifactStoreError("bootstrap token is required to mint the runtime identity")
        if not caller_id:
            raise RuntimeArtifactStoreError("runtime identity caller_id is required")
        if not expected_job_id:
            raise RuntimeArtifactStoreError("expected runtime identity job_id is required")
        response = _request_json(
            "POST",
            _endpoint(s10_url, "/v1/runtime-identities"),
            body={"caller_id": caller_id, "ttl_s": _positive_ttl(ttl_s)},
            bearer_token=bootstrap_token,
            timeout_s=timeout_s,
        )
        access_token = _required_str(response, "access_token", context="runtime identity response")
        identity = _required_mapping(response, "identity", context="runtime identity response")
        actual_job_id = _required_str(identity, "job_id", context="runtime identity response identity")
        actual_caller_id = _required_str(identity, "caller_id", context="runtime identity response identity")
        if actual_job_id != expected_job_id:
            raise RuntimeArtifactStoreError(
                f"runtime identity job_id mismatch: expected {expected_job_id!r}, received {actual_job_id!r}"
            )
        if actual_caller_id != caller_id:
            raise RuntimeArtifactStoreError(
                f"runtime identity caller_id mismatch: expected {caller_id!r}, received {actual_caller_id!r}"
            )
        return cls(
            s10_url=_normalized_base_url(s10_url),
            access_token=access_token,
            caller_id=caller_id,
            job_id=actual_job_id,
            timeout_s=timeout_s,
        )

    @classmethod
    def from_access_token(
        cls,
        *,
        s10_url: str,
        access_token: str,
        caller_id: str,
        expected_job_id: str,
        timeout_s: float = 10.0,
    ) -> "RuntimeIdentitySession":
        if not access_token:
            raise RuntimeArtifactStoreError("runtime access token is required")
        if not caller_id:
            raise RuntimeArtifactStoreError("runtime identity caller_id is required")
        if not expected_job_id:
            raise RuntimeArtifactStoreError("expected runtime identity job_id is required")
        return cls(
            s10_url=_normalized_base_url(s10_url),
            access_token=access_token,
            caller_id=caller_id,
            job_id=expected_job_id,
            timeout_s=timeout_s,
        )

    def mint_scope(self, *, ttl_s: int = DEFAULT_RUNTIME_TOKEN_TTL_S) -> dict[str, Any]:
        response = _request_json(
            "POST",
            _endpoint(self.s10_url, "/v1/scope-tokens"),
            body={"ttl_s": _positive_ttl(ttl_s)},
            bearer_token=self.access_token,
            timeout_s=self.timeout_s,
        )
        if _required_str(response, "job_id", context="scope token response") != self.job_id:
            raise RuntimeArtifactStoreError("scope token job_id mismatch")
        _required_str(response, "scope_id", context="scope token response")
        _required_str(response, "signature", context="scope token response")
        _required_mapping(response, "scopes", context="scope token response")
        return response

    def mint_budget(self, *, ttl_s: int = DEFAULT_RUNTIME_TOKEN_TTL_S) -> dict[str, Any]:
        response = _request_json(
            "POST",
            _endpoint(self.s10_url, "/v1/budget-tokens"),
            body={"ttl_s": _positive_ttl(ttl_s)},
            bearer_token=self.access_token,
            timeout_s=self.timeout_s,
        )
        if _required_str(response, "job_id", context="budget token response") != self.job_id:
            raise RuntimeArtifactStoreError("budget token job_id mismatch")
        _required_str(response, "budget_id", context="budget token response")
        _required_str(response, "signature", context="budget token response")
        return response


def runtime_identity_session(
    *,
    s10_url: str,
    caller_id: str,
    expected_job_id: str,
    bootstrap_token: str | None = None,
    access_token: str | None = None,
    ttl_s: int = DEFAULT_RUNTIME_TOKEN_TTL_S,
    timeout_s: float = 10.0,
) -> RuntimeIdentitySession:
    """Create one runtime session from exactly one deployment credential."""

    has_bootstrap = bool(bootstrap_token)
    has_access_token = bool(access_token)
    if has_bootstrap == has_access_token:
        raise RuntimeArtifactStoreError("runtime session requires exactly one bootstrap or access credential")
    if has_access_token:
        assert access_token is not None
        return RuntimeIdentitySession.from_access_token(
            s10_url=s10_url,
            access_token=access_token,
            caller_id=caller_id,
            expected_job_id=expected_job_id,
            timeout_s=timeout_s,
        )
    if has_bootstrap:
        assert bootstrap_token is not None
        return RuntimeIdentitySession.from_bootstrap(
            s10_url=s10_url,
            bootstrap_token=bootstrap_token,
            caller_id=caller_id,
            expected_job_id=expected_job_id,
            ttl_s=ttl_s,
            timeout_s=timeout_s,
        )
    raise RuntimeArtifactStoreError("runtime session requires an access token or bootstrap credential")


class S10S8ArtifactStore:
    """C4-compatible store facade backed only by S10 broker and S8 read APIs."""

    def __init__(
        self,
        *,
        session: RuntimeIdentitySession,
        s8_url: str,
        scope_ttl_s: int = DEFAULT_RUNTIME_TOKEN_TTL_S,
    ) -> None:
        self._session = session
        self._s8_url = _normalized_base_url(s8_url)
        self._scope_ttl_s = _positive_ttl(scope_ttl_s)
        self._scope_token: dict[str, Any] | None = None

    @property
    def job_id(self) -> str:
        return self._session.job_id

    def create_artifact(
        self,
        *,
        kind: str,
        payload: Any,
        producer: Producer,
        lineage: Lineage,
        artifact_ref: str | None = None,
        claim_tier: str = "ran-toy",
        validation_report_ref: str | None = None,
        created_at: str | None = None,
    ) -> ArtifactRecord:
        if producer.job_id not in {None, self.job_id}:
            raise RuntimeArtifactStoreError("producer job_id does not match the runtime identity")
        if lineage.job_id not in {None, self.job_id}:
            raise RuntimeArtifactStoreError("lineage job_id does not match the runtime identity")
        if created_at is not None:
            raise RuntimeArtifactStoreError("runtime artifact timestamps are assigned by the C4 store")
        body: dict[str, Any] = {
            "scope_token": self._scope(),
            "kind": kind,
            "payload": _jsonable(payload),
            "producer": _jsonable(producer),
            "lineage": _jsonable(lineage),
            "claim_tier": claim_tier,
        }
        if artifact_ref is not None:
            body["artifact_ref"] = artifact_ref
        if validation_report_ref is not None:
            body["validation_report_ref"] = validation_report_ref
        response = _request_json(
            "POST",
            _endpoint(self._session.s10_url, "/v1/store/artifacts"),
            body=body,
            bearer_token=self._session.access_token,
            timeout_s=self._session.timeout_s,
        )
        return _artifact_record_from_response(response, context="S10 broker response")

    def get_record(self, artifact_ref: str) -> ArtifactRecord:
        response = self._s8_get(f"/v1/artifacts/{artifact_ref}/record")
        return _artifact_record_from_response(response, context="S8 record response")

    def get_artifact_record(self, artifact_ref: str) -> ArtifactRecord:
        return self.get_record(artifact_ref)

    def get_artifact(self, artifact_ref: str) -> bytes:
        payload = self._s8_get(f"/v1/artifacts/{artifact_ref}/payload")
        return canonical_json_bytes(payload)

    def get_lineage(self, artifact_ref: str, *, direction: str = "both") -> LineageGraph:
        if direction not in {"ancestors", "descendants", "both"}:
            raise RuntimeArtifactStoreError("lineage direction must be ancestors, descendants, or both")
        response = self._s8_get(f"/v1/lineage/{artifact_ref}", query={"direction": direction})
        nodes_raw = _required_sequence(response, "nodes", context="S8 lineage response")
        edges_raw = _required_sequence(response, "edges", context="S8 lineage response")
        return LineageGraph(
            nodes=tuple(_artifact_record_from_response(_mapping(item, "S8 lineage node"), context="S8 lineage node") for item in nodes_raw),
            edges=tuple(_lineage_edge_from_response(_mapping(item, "S8 lineage edge")) for item in edges_raw),
        )

    def query_artifacts(
        self,
        filters: ArtifactQueryFilter | Mapping[str, Any] | None = None,
        *,
        page_size: int | None = None,
        page_token: int | None = None,
    ) -> ArtifactQueryPage:
        query: dict[str, str] = {}
        for key, value in _query_filter_items(filters):
            query[key] = value
        if page_size is not None:
            query["page_size"] = str(page_size)
        if page_token is not None:
            query["page_token"] = str(page_token)
        response = self._s8_get("/v1/artifacts", query=query)
        records = _required_sequence(response, "records", context="S8 artifact query response")
        next_page_token = response.get("next_page_token")
        if next_page_token is not None and not isinstance(next_page_token, int):
            raise RuntimeArtifactStoreError("S8 artifact query response next_page_token must be an integer or null")
        return ArtifactQueryPage(
            records=tuple(
                _artifact_record_from_response(_mapping(item, "S8 artifact query record"), context="S8 artifact query record")
                for item in records
            ),
            next_page_token=next_page_token,
        )

    def insert_lineage_edge(self, _source_ref: str, _target_ref: str, _edge_type: str) -> None:
        raise RuntimeArtifactStoreError("S8 runtime artifact store has no direct lineage-edge mutation route")

    def _scope(self) -> dict[str, Any]:
        if self._scope_token is None:
            self._scope_token = self._session.mint_scope(ttl_s=self._scope_ttl_s)
        return dict(self._scope_token)

    def _s8_get(self, path: str, *, query: Mapping[str, str] | None = None) -> dict[str, Any]:
        url = _endpoint(self._s8_url, path)
        if query:
            url = f"{url}?{urlparse.urlencode(dict(query))}"
        return _request_json(
            "GET",
            url,
            bearer_token=self._session.access_token,
            timeout_s=self._session.timeout_s,
        )


def _request_json(
    method: str,
    url: str,
    *,
    body: Mapping[str, Any] | None = None,
    bearer_token: str,
    timeout_s: float,
) -> dict[str, Any]:
    data = None
    headers = {"Authorization": f"Bearer {bearer_token}"}
    if body is not None:
        data = canonical_json_bytes(_jsonable(body))
        headers["Content-Type"] = "application/json"
    request = urlrequest.Request(url, data=data, headers=headers, method=method)
    try:
        with urlrequest.urlopen(request, timeout=timeout_s) as response:
            raw = response.read()
    except urlerror.HTTPError as exc:
        response_body = _http_error_body(exc)
        raise RuntimeArtifactStoreError(f"{method} {url} failed with HTTP {exc.code}: {response_body}") from exc
    except OSError as exc:
        raise RuntimeArtifactStoreError(f"{method} {url} could not be reached: {exc}") from exc
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeArtifactStoreError(f"{method} {url} returned invalid JSON") from exc
    if not isinstance(parsed, dict):
        raise RuntimeArtifactStoreError(f"{method} {url} returned a non-object JSON response")
    return parsed


def _artifact_record_from_response(value: Mapping[str, Any], *, context: str) -> ArtifactRecord:
    artifact_ref = _required_str(value, "artifact_ref", context=context)
    kind = _required_str(value, "kind", context=context)
    content_hash = _required_str(value, "content_hash", context=context)
    size_bytes = _required_int(value, "size_bytes", context=context)
    claim_tier = _required_str(value, "claim_tier", context=context)
    created_at = _required_str(value, "created_at", context=context)
    producer = _required_mapping(value, "producer", context=context)
    lineage = _required_mapping(value, "lineage", context=context)
    return ArtifactRecord(
        artifact_ref=artifact_ref,
        kind=kind,
        content_hash=content_hash,
        size_bytes=size_bytes,
        producer=Producer(
            subsystem=_required_str(producer, "subsystem", context=f"{context} producer"),
            version=_required_str(producer, "version", context=f"{context} producer"),
            actor_id=_optional_str(producer.get("actor_id")),
            job_id=_optional_str(producer.get("job_id")),
        ),
        lineage=Lineage(
            input_refs=tuple(_required_string_sequence(lineage, "input_refs", context=f"{context} lineage")),
            code_ref=_required_str(lineage, "code_ref", context=f"{context} lineage"),
            environment_digest=_required_str(lineage, "environment_digest", context=f"{context} lineage"),
            seeds=tuple(_string_sequence(lineage.get("seeds"), context=f"{context} lineage seeds")),
            actor_id=_optional_str(lineage.get("actor_id")),
            job_id=_optional_str(lineage.get("job_id")),
            contamination_index_version=_optional_str(lineage.get("contamination_index_version")),
        ),
        claim_tier=claim_tier,
        validation_report_ref=_optional_str(value.get("validation_report_ref")),
        created_at=created_at,
    )


def _lineage_edge_from_response(value: Mapping[str, Any]) -> LineageEdge:
    return LineageEdge(
        source_ref=_required_str(value, "source_ref", context="S8 lineage edge"),
        target_ref=_required_str(value, "target_ref", context="S8 lineage edge"),
        edge_type=_required_str(value, "edge_type", context="S8 lineage edge"),
    )


def _query_filter_items(filters: ArtifactQueryFilter | Mapping[str, Any] | None) -> Sequence[tuple[str, str]]:
    if filters is None:
        return ()
    source = asdict(filters) if isinstance(filters, ArtifactQueryFilter) else dict(filters)
    items: list[tuple[str, str]] = []
    for key, value in source.items():
        if value is None:
            continue
        if not isinstance(value, (str, int, float, bool)):
            raise RuntimeArtifactStoreError(f"S8 query filter {key!r} must be scalar")
        items.append((str(key), str(value)))
    return tuple(items)


def _endpoint(base_url: str, path: str) -> str:
    if not path.startswith("/"):
        raise RuntimeArtifactStoreError("runtime endpoint path must start with '/'")
    return f"{_normalized_base_url(base_url)}{path}"


def _normalized_base_url(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise RuntimeArtifactStoreError("runtime endpoint base URL is required")
    return value.rstrip("/")


def _positive_ttl(value: int) -> int:
    ttl = int(value)
    if ttl <= 0:
        raise RuntimeArtifactStoreError("runtime token ttl_s must be positive")
    return ttl


def _required_str(value: Mapping[str, Any], field: str, *, context: str) -> str:
    item = value.get(field)
    if not isinstance(item, str) or not item:
        raise RuntimeArtifactStoreError(f"{context} requires non-empty {field}")
    return item


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise RuntimeArtifactStoreError("runtime response optional string field has an invalid type")
    return value


def _required_int(value: Mapping[str, Any], field: str, *, context: str) -> int:
    item = value.get(field)
    if isinstance(item, bool) or not isinstance(item, int):
        raise RuntimeArtifactStoreError(f"{context} requires integer {field}")
    return item


def _required_mapping(value: Mapping[str, Any], field: str, *, context: str) -> dict[str, Any]:
    return _mapping(value.get(field), f"{context} {field}")


def _mapping(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RuntimeArtifactStoreError(f"{context} must be an object")
    return dict(value)


def _required_sequence(value: Mapping[str, Any], field: str, *, context: str) -> Sequence[Any]:
    item = value.get(field)
    if not isinstance(item, list):
        raise RuntimeArtifactStoreError(f"{context} requires array {field}")
    return item


def _required_string_sequence(value: Mapping[str, Any], field: str, *, context: str) -> Sequence[str]:
    if field not in value:
        raise RuntimeArtifactStoreError(f"{context} requires array {field}")
    return _string_sequence(value[field], context=context)


def _string_sequence(value: Any, *, context: str) -> Sequence[str]:
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)) or not all(isinstance(item, str) for item in value):
        raise RuntimeArtifactStoreError(f"{context} must be an array of strings")
    return tuple(value)


def _jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return _jsonable(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _http_error_body(exc: urlerror.HTTPError) -> str:
    try:
        raw = exc.read().decode("utf-8")
    except Exception:
        return "unavailable"
    return raw[:512] if raw else "empty"
