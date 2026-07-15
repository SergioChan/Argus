"""Durable S10 audit ledger with a Rust-only append path."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime
import json
import os
from pathlib import Path
import subprocess
import threading
from typing import Any, Callable

from argus_core import AuditEvent, canonical_json_bytes, hash_bytes, hash_json
from argus_core.s10 import AuditVerification, audit_event_hash


ZERO_HASH = "blake3:" + "0" * 64


class AuditLedgerWriteError(RuntimeError):
    """Raised when the Rust audit writer cannot commit an event."""


class AuditAnchorUnavailableError(AuditLedgerWriteError):
    """Raised when the write-once C4 anchor cannot be created and verified."""


class PostgresAuditLedger:
    """Read/query facade around the Rust-owned PostgreSQL audit writer."""

    kind = "postgres-rust-subprocess"

    def __init__(
        self,
        *,
        dsn: str,
        writer_binary: str | os.PathLike[str],
        writer_role: str,
        anchor_url: str,
        anchor_auth_token: str,
        allow_insecure_anchor: bool,
        anchor_loader: Callable[[str], dict[str, Any]],
        writer_timeout_s: float = 45.0,
    ) -> None:
        if not dsn:
            raise ValueError("audit PostgreSQL DSN is required")
        if not writer_role:
            raise ValueError("audit PostgreSQL writer role is required")
        if not anchor_url:
            raise ValueError("audit anchor URL is required")
        if not anchor_auth_token:
            raise ValueError("audit anchor auth token is required")
        if writer_timeout_s <= 0:
            raise ValueError("audit writer timeout must be positive")
        self._dsn = dsn
        self._writer_binary = Path(writer_binary)
        self._writer_role = writer_role
        self._anchor_url = anchor_url
        self._anchor_auth_token = anchor_auth_token
        self._allow_insecure_anchor = allow_insecure_anchor
        self._anchor_loader = anchor_loader
        self._writer_timeout_s = writer_timeout_s
        self._trace_ids: dict[str, str] = {}
        self._trace_lock = threading.RLock()

    def bind_trace(self, *, job_id: str, trace_id: str) -> None:
        if not job_id or not trace_id:
            raise ValueError("audit trace binding requires job_id and trace_id")
        with self._trace_lock:
            self._trace_ids[job_id] = trace_id

    def append(self, event_type: str, payload: dict[str, Any]) -> AuditEvent:
        if not isinstance(event_type, str) or not event_type:
            raise ValueError("audit event_type is required")
        if not isinstance(payload, dict):
            raise ValueError("audit payload must be an object")
        try:
            canonical_payload = json.loads(canonical_json_bytes(payload))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("audit payload must contain only canonical JSON values") from exc
        job_id = canonical_payload.get("job_id")
        if isinstance(job_id, str) and job_id and "trace_id" not in canonical_payload:
            with self._trace_lock:
                trace_id = self._trace_ids.get(job_id)
            if trace_id is not None:
                canonical_payload["trace_id"] = trace_id
        if not self._writer_binary.is_file():
            raise AuditLedgerWriteError(f"audit writer binary not found: {self._writer_binary}")
        env = os.environ.copy()
        env.update(
            {
                "ARGUS_S10_AUDIT_POSTGRES_DSN": self._dsn,
                "ARGUS_S10_AUDIT_POSTGRES_ROLE": self._writer_role,
                "ARGUS_S10_AUDIT_ANCHOR_URL": self._anchor_url,
                "ARGUS_S10_AUDIT_ANCHOR_AUTH_TOKEN": self._anchor_auth_token,
            }
        )
        if self._allow_insecure_anchor:
            env["ARGUS_S10_ALLOW_INSECURE_AUDIT_ANCHOR"] = "1"
        else:
            env.pop("ARGUS_S10_ALLOW_INSECURE_AUDIT_ANCHOR", None)
        try:
            completed = subprocess.run(
                [str(self._writer_binary)],
                input=canonical_json_bytes(
                    {"event_type": event_type, "payload": canonical_payload}
                ).decode("utf-8"),
                text=True,
                capture_output=True,
                check=False,
                timeout=self._writer_timeout_s,
                env=env,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AuditLedgerWriteError("audit Rust writer is unavailable") from exc
        if completed.returncode != 0:
            message = (completed.stderr or completed.stdout).strip() or "audit Rust writer failed"
            if "audit anchor" in message.lower():
                raise AuditAnchorUnavailableError(message)
            raise AuditLedgerWriteError(message)
        try:
            result = json.loads(completed.stdout)
            event = AuditEvent(
                sequence=int(result["sequence"]),
                event_type=str(result["event_type"]),
                payload=dict(result["payload"]),
                previous_hash=str(result["previous_hash"]),
                event_hash=str(result["event_hash"]),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise AuditLedgerWriteError("audit Rust writer returned an invalid response") from exc
        if event.event_type != event_type or event.payload != canonical_payload:
            summary = _json_mismatch_summary(canonical_payload, event.payload)
            raise AuditLedgerWriteError(
                "audit Rust writer returned a mismatched event "
                f"(event_type_match={event.event_type == event_type}; {summary})"
            )
        return event

    def events(self) -> tuple[AuditEvent, ...]:
        return self.query()

    def query(
        self,
        *,
        job_id: str | None = None,
        event_type: str | None = None,
        severity: str | None = None,
        from_time: datetime | None = None,
        to_time: datetime | None = None,
    ) -> tuple[AuditEvent, ...]:
        import psycopg

        clauses: list[str] = []
        parameters: list[Any] = []
        if job_id is not None:
            clauses.append("payload ->> 'job_id' = %s")
            parameters.append(job_id)
        if event_type is not None:
            clauses.append("event_type = %s")
            parameters.append(event_type)
        if severity is not None:
            clauses.append("payload ->> 'severity' = %s")
            parameters.append(severity)
        if from_time is not None:
            clauses.append("created_at >= %s")
            parameters.append(from_time)
        if to_time is not None:
            clauses.append("created_at <= %s")
            parameters.append(to_time)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT sequence, event_type, payload, previous_hash, event_hash "
                    f"FROM s10.audit_event{where} ORDER BY sequence;",
                    parameters,
                )
                return tuple(_event_from_row(row) for row in cur.fetchall())

    def verify_chain(
        self,
        *,
        from_sequence: int | None = None,
        to_sequence: int | None = None,
    ) -> AuditVerification:
        lower = from_sequence or 1
        if lower < 1 or (to_sequence is not None and to_sequence < lower):
            raise ValueError("audit verification range is invalid")
        rows = self._verification_rows()
        if not rows:
            return AuditVerification(valid=True)
        by_sequence = {int(row[0]): row for row in rows}
        upper = to_sequence or max(by_sequence)
        previous_hash = ZERO_HASH
        previous_root = ZERO_HASH
        if lower > 1:
            previous = by_sequence.get(lower - 1)
            if previous is None:
                return AuditVerification(
                    valid=False,
                    break_sequence=lower,
                    anchor_mismatch=True,
                    reason="missing_previous_sequence",
                )
            previous_hash = str(previous[4])
            previous_root = str(previous[7])

        for sequence in range(lower, upper + 1):
            row = by_sequence.get(sequence)
            if row is None:
                return AuditVerification(
                    valid=False,
                    break_sequence=sequence,
                    anchor_mismatch=True,
                    reason="missing_sequence",
                )
            event = _event_from_row(row)
            anchor_previous_root = str(row[6]) if row[6] is not None else ""
            anchor_root = str(row[7]) if row[7] is not None else ""
            anchor_ref = str(row[8]) if row[8] is not None else ""
            anchor_content_hash = str(row[9]) if row[9] is not None else ""
            expected_event_hash = audit_event_hash(
                event.sequence,
                event.event_type,
                event.payload,
                previous_hash,
            )
            expected_root = _next_merkle_root(previous_root, expected_event_hash, event.sequence)
            anchor_mismatch = (
                anchor_previous_root != previous_root
                or anchor_root != expected_root
                or not anchor_ref
                or not anchor_content_hash
            )
            if event.previous_hash != previous_hash or event.event_hash != expected_event_hash:
                return AuditVerification(
                    valid=False,
                    break_sequence=sequence,
                    anchor_mismatch=anchor_mismatch,
                    reason="event_hash_mismatch",
                )
            if anchor_mismatch:
                return AuditVerification(
                    valid=False,
                    break_sequence=sequence,
                    anchor_mismatch=True,
                    reason="database_anchor_mismatch",
                )
            expected_anchor = {
                "schema": "argus.s10.audit-anchor.v1",
                "sequence": sequence,
                "previous_root": previous_root,
                "root": expected_root,
                "event_hash": expected_event_hash,
            }
            try:
                loaded = self._anchor_loader(anchor_ref)
                external_anchor = loaded.get("payload") if loaded.get("representation") == "payload" else loaded
            except Exception:
                return AuditVerification(
                    valid=False,
                    break_sequence=sequence,
                    anchor_mismatch=True,
                    reason="external_anchor_unavailable",
                )
            if (
                external_anchor != expected_anchor
                or hash_json(external_anchor) != anchor_content_hash
            ):
                return AuditVerification(
                    valid=False,
                    break_sequence=sequence,
                    anchor_mismatch=True,
                    reason="external_anchor_mismatch",
                )
            previous_hash = event.event_hash
            previous_root = expected_root
        return AuditVerification(valid=True)

    def _verification_rows(self) -> list[tuple[Any, ...]]:
        import psycopg

        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        e.sequence,
                        e.event_type,
                        e.payload,
                        e.previous_hash,
                        e.event_hash,
                        e.created_at,
                        a.previous_root,
                        a.root,
                        a.artifact_ref,
                        a.content_hash
                    FROM s10.audit_event AS e
                    LEFT JOIN s10.audit_anchor AS a USING (sequence)
                    ORDER BY e.sequence;
                    """
                )
                return list(cur.fetchall())


def _event_from_row(row: tuple[Any, ...]) -> AuditEvent:
    return AuditEvent(
        sequence=int(row[0]),
        event_type=str(row[1]),
        payload=deepcopy(dict(row[2])),
        previous_hash=str(row[3]),
        event_hash=str(row[4]),
    )


def _json_mismatch_summary(expected: Any, actual: Any) -> str:
    differences: list[str] = []
    _collect_json_mismatches(expected, actual, path="$", differences=differences, limit=8)
    detail = ",".join(differences) if differences else "$:value"
    return f"expected={hash_json(expected)},actual={hash_json(actual)};{detail}"


def _collect_json_mismatches(
    expected: Any,
    actual: Any,
    *,
    path: str,
    differences: list[str],
    limit: int,
) -> None:
    if len(differences) >= limit:
        return
    if type(expected) is not type(actual):
        differences.append(f"{path}:type({type(expected).__name__}!={type(actual).__name__})")
        return
    if isinstance(expected, dict):
        expected_keys = set(expected)
        actual_keys = set(actual)
        if expected_keys != actual_keys:
            differences.append(
                f"{path}:keys(missing={len(expected_keys - actual_keys)},extra={len(actual_keys - expected_keys)})"
            )
        for key in sorted(expected_keys & actual_keys):
            _collect_json_mismatches(
                expected[key],
                actual[key],
                path=f"{path}.{key}",
                differences=differences,
                limit=limit,
            )
        return
    if isinstance(expected, list):
        if len(expected) != len(actual):
            differences.append(f"{path}:length({len(expected)}!={len(actual)})")
        for index, (expected_item, actual_item) in enumerate(zip(expected, actual)):
            _collect_json_mismatches(
                expected_item,
                actual_item,
                path=f"{path}[{index}]",
                differences=differences,
                limit=limit,
            )
        return
    if expected != actual:
        differences.append(f"{path}:value({type(expected).__name__})")


def _next_merkle_root(previous_root: str, event_hash: str, sequence: int) -> str:
    return hash_bytes(f"{previous_root}|{event_hash}|{sequence}".encode("utf-8"))
