"""Runtime persistence backends for the deployed S8 writer service."""

from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime
from io import BytesIO
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
from typing import Any

from argusverify import C3ReportVerifier, InMemoryVerifierTrustStore

from argus_core import (
    ArtifactRecord,
    ArtifactQueryFilter,
    ArtifactQueryPage,
    HashMismatchError,
    InMemoryArtifactStore,
    Lineage,
    LineageGraph,
    Producer,
    ReproducibilityCheck,
    ReproducibilityManifest,
    SCRATCH_BUCKET,
    WRITE_ONCE_BUCKET,
    hash_json,
)
from argus_core.s8 import _assert_known_bucket_class, _assert_payload_matches_hash, _object_name


class MinioObjectStore:
    """S8 ObjectStoreFacade backed by a MinIO/S3 bucket."""

    def __init__(
        self,
        *,
        endpoint: str,
        access_key: str,
        secret_key: str,
        bucket: str,
        secure: bool = False,
    ) -> None:
        from minio import Minio

        self.bucket = bucket
        self._client = Minio(endpoint, access_key=access_key, secret_key=secret_key, secure=secure)
        if not self._client.bucket_exists(bucket):
            self._client.make_bucket(bucket)

    def put(self, content_hash: str, payload: bytes, *, bucket_class: str) -> None:
        _assert_known_bucket_class(bucket_class)
        _assert_payload_matches_hash(content_hash, payload)
        existing_key = self._object_key(content_hash)
        if existing_key is not None:
            existing = self._get_key(existing_key)
            _assert_payload_matches_hash(content_hash, existing)
            if existing != payload:
                raise HashMismatchError(f"existing object bytes do not match {content_hash}")
            if bucket_class == WRITE_ONCE_BUCKET and existing_key.split("/", 1)[0] == SCRATCH_BUCKET:
                self.promote_to_write_once(content_hash)
            return

        key = self._key_for(content_hash, bucket_class)
        self._client.put_object(
            self.bucket,
            key,
            BytesIO(payload),
            length=len(payload),
            content_type="application/json",
        )

    def get(self, content_hash: str) -> bytes:
        key = self._object_key(content_hash)
        if key is None:
            raise KeyError(content_hash)
        payload = self._get_key(key)
        _assert_payload_matches_hash(content_hash, payload)
        return payload

    def promote_to_write_once(self, content_hash: str) -> None:
        write_once_key = self._key_for(content_hash, WRITE_ONCE_BUCKET)
        scratch_key = self._key_for(content_hash, SCRATCH_BUCKET)
        if self._key_exists(write_once_key):
            payload = self._get_key(write_once_key)
            _assert_payload_matches_hash(content_hash, payload)
            if self._key_exists(scratch_key):
                scratch_payload = self._get_key(scratch_key)
                _assert_payload_matches_hash(content_hash, scratch_payload)
                if scratch_payload != payload:
                    raise HashMismatchError(f"scratch object bytes do not match {content_hash}")
                self._client.remove_object(self.bucket, scratch_key)
            return
        if not self._key_exists(scratch_key):
            raise KeyError(content_hash)
        payload = self._get_key(scratch_key)
        _assert_payload_matches_hash(content_hash, payload)
        self._client.put_object(
            self.bucket,
            write_once_key,
            BytesIO(payload),
            length=len(payload),
            content_type="application/json",
        )
        self._client.remove_object(self.bucket, scratch_key)

    def bucket_class(self, content_hash: str) -> str:
        key = self._object_key(content_hash)
        if key is None:
            raise KeyError(content_hash)
        return key.split("/", 1)[0]

    @property
    def object_count(self) -> int:
        names = {
            item.object_name.split("/", 1)[1]
            for item in self._client.list_objects(self.bucket, recursive=True)
            if item.object_name and "/" in item.object_name
        }
        return len(names)

    def overwrite_for_test(self, content_hash: str, payload: bytes) -> None:
        key = self._object_key(content_hash)
        if key is None:
            raise KeyError(content_hash)
        self._client.put_object(
            self.bucket,
            key,
            BytesIO(payload),
            length=len(payload),
            content_type="application/json",
        )

    def _object_key(self, content_hash: str) -> str | None:
        write_once_key = self._key_for(content_hash, WRITE_ONCE_BUCKET)
        if self._key_exists(write_once_key):
            return write_once_key
        scratch_key = self._key_for(content_hash, SCRATCH_BUCKET)
        if self._key_exists(scratch_key):
            return scratch_key
        return None

    def _key_for(self, content_hash: str, bucket_class: str) -> str:
        return f"{bucket_class}/{_object_name(content_hash)}"

    def _key_exists(self, key: str) -> bool:
        from minio.error import S3Error

        try:
            self._client.stat_object(self.bucket, key)
            return True
        except S3Error as exc:
            if exc.code in {"NoSuchKey", "NoSuchObject"}:
                return False
            raise

    def _get_key(self, key: str) -> bytes:
        response = self._client.get_object(self.bucket, key)
        try:
            return response.read()
        finally:
            response.close()
            response.release_conn()


class SubprocessRustLedgerWriter:
    def __init__(
        self,
        *,
        command: list[str],
        dsn: str,
        db_role: str | None,
        checkpoint_signer_url: str,
        checkpoint_signer_auth_token: str,
        allow_insecure_checkpoint_signer: bool = False,
    ) -> None:
        self._command = command
        self._dsn = dsn
        self._db_role = db_role
        self._checkpoint_signer_url = checkpoint_signer_url
        self._checkpoint_signer_auth_token = checkpoint_signer_auth_token
        self._allow_insecure_checkpoint_signer = allow_insecure_checkpoint_signer
        self.checkpoint_signer_kind = _checkpoint_signer_kind(
            checkpoint_signer_url,
            allow_insecure_checkpoint_signer=allow_insecure_checkpoint_signer,
        )

    def commit_record(self, record: ArtifactRecord) -> dict[str, Any]:
        env = {
            **os.environ,
            "ARGUS_S8_RUST_LEDGER_DSN": self._dsn,
            "ARGUS_S8_CHECKPOINT_SIGNER_URL": self._checkpoint_signer_url,
            "ARGUS_S8_CHECKPOINT_SIGNER_AUTH_TOKEN": self._checkpoint_signer_auth_token,
        }
        if self._allow_insecure_checkpoint_signer:
            env["ARGUS_S8_ALLOW_INSECURE_CHECKPOINT_SIGNER"] = "1"
        else:
            env.pop("ARGUS_S8_ALLOW_INSECURE_CHECKPOINT_SIGNER", None)
        env.pop("ARGUS_S8_CHECKPOINT_SIGNING_KEY", None)
        env.pop("ARGUS_S8_CHECKPOINT_SIGNER_KEY_ID", None)
        if self._db_role:
            env["ARGUS_S8_RUST_LEDGER_ROLE"] = self._db_role
        completed = subprocess.run(
            self._command,
            input=json.dumps(_rust_ledger_draft(record), separators=(",", ":"), sort_keys=True),
            text=True,
            capture_output=True,
            check=False,
            env=env,
        )
        if completed.returncode != 0:
            raise RuntimeError(f"Rust S8 ledger writer failed: {completed.stderr.strip()}")
        if not completed.stdout.strip():
            return {"status": "ok", "checkpoint": None}
        result = json.loads(completed.stdout)
        if result.get("status") != "ok":
            raise RuntimeError(f"Rust S8 ledger writer returned unexpected status: {result!r}")
        return result


class PostgresArtifactStore:
    """C4 store that writes payload bytes to MinIO and the append-only ledger to PostgreSQL."""

    requires_service_refresh = False

    def __init__(
        self,
        *,
        dsn: str,
        object_store: MinioObjectStore,
        db_role: str | None = None,
        ledger_writer: SubprocessRustLedgerWriter | None = None,
        report_verifier: C3ReportVerifier | None = None,
    ) -> None:
        if ledger_writer is None:
            raise RuntimeError("S8 Rust ledger writer is required")
        self._dsn = dsn
        self._object_store = object_store
        self._db_role = db_role
        self._ledger_writer = ledger_writer
        self._report_verifier = report_verifier
        self.ledger_writer_kind = getattr(ledger_writer, "ledger_writer_kind", "rust-subprocess")
        self.checkpoint_signer_kind = getattr(ledger_writer, "checkpoint_signer_kind", "unconfigured")
        self.report_verifier_kind = "argusverify" if report_verifier is not None else "unconfigured"
        self._snapshot = self._snapshot_store()
        self.refresh()

    def refresh(self) -> None:
        snapshot = self._snapshot_store()
        for row in self._fetch_records():
            payload_bytes = self._object_store.get(str(row["content_hash"]))
            record = _record_from_row(row, size_bytes=len(payload_bytes))
            payload = json.loads(payload_bytes.decode("utf-8"))
            snapshot.create_artifact(
                artifact_ref=record.artifact_ref,
                kind=record.kind,
                payload=payload,
                producer=record.producer,
                lineage=record.lineage,
                claim_tier=record.claim_tier,
                validation_report_ref=record.validation_report_ref,
                created_at=record.created_at,
            )
        self._snapshot = snapshot

    def _snapshot_store(self) -> InMemoryArtifactStore:
        return InMemoryArtifactStore(
            object_store=self._object_store,
            report_verifier=self._report_verifier,
        )

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
        self.refresh()
        before_count = self._snapshot.record_count
        record = self._snapshot.create_artifact(
            kind=kind,
            payload=payload,
            producer=producer,
            lineage=lineage,
            artifact_ref=artifact_ref,
            claim_tier=claim_tier,
            validation_report_ref=validation_report_ref,
            created_at=created_at,
        )
        if self._snapshot.record_count == before_count:
            return record
        self._commit_record(record)
        return self.get_artifact_record(record.artifact_ref)

    def get_artifact(self, ref: str) -> bytes:
        row = self._fetch_record(ref, require_unique_record=False)
        return self._object_store.get(str(row["content_hash"]))

    def get_record(self, artifact_ref: str) -> ArtifactRecord:
        row = self._fetch_record(artifact_ref, require_unique_record=True)
        payload_bytes = self._object_store.get(str(row["content_hash"]))
        return _record_from_row(row, size_bytes=len(payload_bytes))

    def get_artifact_record(self, ref: str) -> ArtifactRecord:
        row = self._fetch_record(ref, require_unique_record=True)
        return self._record_from_row_with_metadata_size(row)

    def get_lineage(
        self,
        artifact_ref: str,
        *,
        direction: str = "both",
        edge_types: set[str] | None = None,
        max_depth: int | None = None,
    ) -> LineageGraph:
        self.refresh()
        return self._snapshot.get_lineage(
            artifact_ref,
            direction=direction,
            edge_types=edge_types,
            max_depth=max_depth,
        )

    def query_impact_set(
        self,
        seed_refs: tuple[str, ...],
        *,
        edge_types: set[str] | None = None,
    ) -> tuple[ArtifactRecord, ...]:
        self.refresh()
        return self._snapshot.query_impact_set(seed_refs, edge_types=edge_types)

    def query_artifacts(
        self,
        query: ArtifactQueryFilter | dict[str, Any] | None = None,
        *,
        page_size: int | None = None,
        page_token: int | None = None,
    ) -> tuple[ArtifactRecord, ...]:
        self.refresh()
        return self._snapshot.query_artifacts(query, page_size=page_size, page_token=page_token)

    def query_artifacts_page(
        self,
        query: ArtifactQueryFilter | dict[str, Any] | None = None,
        *,
        page_size: int | None = None,
        page_token: int | None = None,
    ) -> ArtifactQueryPage:
        self.refresh()
        return self._snapshot.query_artifacts_page(query, page_size=page_size, page_token=page_token)

    def get_reproducibility_manifest(self, artifact_ref: str) -> ReproducibilityManifest:
        self.refresh()
        return self._snapshot.get_reproducibility_manifest(artifact_ref)

    def record_reproducibility_check(
        self,
        artifact_ref: str,
        *,
        rerun_payload: Any | None = None,
        rerun_content_hash: str | None = None,
        comparator_id: str | None = None,
        tolerance_id: str | None = None,
    ) -> ReproducibilityCheck:
        self.refresh()
        check = self._snapshot.record_reproducibility_check(
            artifact_ref,
            rerun_payload=rerun_payload,
            rerun_content_hash=rerun_content_hash,
            comparator_id=comparator_id,
            tolerance_id=tolerance_id,
        )
        self._commit_reproducibility_check(check)
        return check

    def export_audit_slice(self, artifact_refs: tuple[str, ...]) -> dict[str, Any]:
        import psycopg

        refs = list(artifact_refs) if artifact_refs else None
        with psycopg.connect(self._dsn) as conn:
            _set_role(conn, self._db_role)
            with conn.cursor() as cur:
                cur.execute("SELECT s8.export_audit_slice(%s::text[]);", (refs,))
                return _jsonb_object(cur.fetchone()[0])

    def verify_audit_slice(self, audit_slice: dict[str, Any]) -> dict[str, Any]:
        import psycopg

        with psycopg.connect(self._dsn) as conn:
            _set_role(conn, self._db_role)
            with conn.cursor() as cur:
                cur.execute("SELECT s8.verify_audit_slice(%s::jsonb);", (json.dumps(audit_slice, sort_keys=True),))
                return _jsonb_object(cur.fetchone()[0])

    def verify_audit_chain(self) -> dict[str, Any]:
        import psycopg

        with psycopg.connect(self._dsn) as conn:
            _set_role(conn, self._db_role)
            with conn.cursor() as cur:
                cur.execute("SELECT s8.verify_audit_chain();")
                return _jsonb_object(cur.fetchone()[0])

    @property
    def record_count(self) -> int:
        import psycopg

        with psycopg.connect(self._dsn) as conn:
            _set_role(conn, self._db_role)
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) FROM s8.artifact_record;")
                return int(cur.fetchone()[0])

    @property
    def object_count(self) -> int:
        return self._object_store.object_count

    def bucket_class_for_artifact(self, artifact_ref: str) -> str:
        row = self._fetch_record(artifact_ref, require_unique_record=True)
        return self._object_store.bucket_class(str(row["content_hash"]))

    def _fetch_record(self, ref: str, *, require_unique_record: bool) -> dict[str, Any]:
        rows = self._fetch_records_by_ref(ref)
        if not rows:
            raise KeyError(ref)
        exact = [row for row in rows if str(row["artifact_id"]) == ref]
        if exact:
            return exact[0]
        if require_unique_record and len(rows) > 1:
            raise KeyError(f"ambiguous content_hash: {ref}")
        return rows[0]

    def _fetch_records_by_ref(self, ref: str) -> list[dict[str, Any]]:
        import psycopg
        from psycopg.rows import dict_row

        with psycopg.connect(self._dsn, row_factory=dict_row) as conn:
            _set_role(conn, self._db_role)
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        artifact_id,
                        content_hash,
                        kind,
                        producer,
                        lineage,
                        claim_tier,
                        validation_report_ref,
                        size_bytes,
                        created_at
                    FROM s8.artifact_record
                    WHERE artifact_id = %s OR content_hash = %s
                    ORDER BY
                        CASE WHEN artifact_id = %s THEN 0 ELSE 1 END,
                        merkle_seq;
                    """,
                    (ref, ref, ref),
                )
                return list(cur.fetchall())

    def _fetch_records(self) -> list[dict[str, Any]]:
        import psycopg
        from psycopg.rows import dict_row

        with psycopg.connect(self._dsn, row_factory=dict_row) as conn:
            _set_role(conn, self._db_role)
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        artifact_id,
                        content_hash,
                        kind,
                        producer,
                        lineage,
                        claim_tier,
                        validation_report_ref,
                        size_bytes,
                        created_at
                    FROM s8.artifact_record
                    ORDER BY merkle_seq;
                    """
                )
                return list(cur.fetchall())

    def _commit_record(self, record: ArtifactRecord) -> None:
        self._ledger_writer.commit_record(record)

    def _commit_reproducibility_check(self, check: ReproducibilityCheck) -> bool:
        import psycopg

        with psycopg.connect(self._dsn) as conn:
            _set_role(conn, self._db_role)
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT s8.record_reproducibility_check(%s, %s, %s, %s, %s);
                    """,
                    (
                        check.check_id,
                        check.artifact_ref,
                        check.rerun_content_hash,
                        check.verdict,
                        check.tolerance_id,
                    ),
                )
                return bool(cur.fetchone()[0])

    def _record_from_row_with_metadata_size(self, row: dict[str, Any]) -> ArtifactRecord:
        size_bytes = row.get("size_bytes")
        if size_bytes is None:
            payload_bytes = self._object_store.get(str(row["content_hash"]))
            size_bytes = len(payload_bytes)
        return _record_from_row(row, size_bytes=int(size_bytes))


def build_postgres_minio_store_from_env(env: dict[str, str]) -> PostgresArtifactStore:
    dsn = _required_env(env, "ARGUS_S8_POSTGRES_DSN")
    if env.get("ARGUS_S8_APPLY_MIGRATIONS", "0") == "1":
        apply_s8_migrations(
            dsn=dsn,
            migrations_dir=Path(env.get("ARGUS_S8_MIGRATIONS_DIR", "/app/db/s8")),
        )
    object_store = MinioObjectStore(
        endpoint=_required_env(env, "ARGUS_S8_MINIO_ENDPOINT"),
        access_key=_required_env(env, "ARGUS_S8_MINIO_ACCESS_KEY"),
        secret_key=_required_env(env, "ARGUS_S8_MINIO_SECRET_KEY"),
        bucket=env.get("ARGUS_S8_MINIO_BUCKET", "argus-s8-objects"),
        secure=env.get("ARGUS_S8_MINIO_SECURE", "0") == "1",
    )
    ledger_writer = _rust_ledger_writer_from_env(env, dsn=dsn, db_role=env.get("ARGUS_S8_POSTGRES_ROLE") or None)
    return PostgresArtifactStore(
        dsn=dsn,
        object_store=object_store,
        db_role=env.get("ARGUS_S8_POSTGRES_ROLE") or None,
        ledger_writer=ledger_writer,
        report_verifier=report_verifier_from_env(env),
    )


def report_verifier_from_env(env: dict[str, str]) -> C3ReportVerifier | None:
    raw_keys = env.get("ARGUS_S8_C3_VERIFIER_KEYS_JSON")
    required = env.get("ARGUS_S8_REQUIRE_REPORT_VERIFIER", "0") == "1"
    if not raw_keys:
        if required:
            raise RuntimeError("ARGUS_S8_C3_VERIFIER_KEYS_JSON is required")
        return None
    try:
        parsed = json.loads(raw_keys)
    except json.JSONDecodeError as exc:
        raise RuntimeError("ARGUS_S8_C3_VERIFIER_KEYS_JSON must be valid JSON") from exc

    trust_store = InMemoryVerifierTrustStore()
    for key in _verifier_key_items(parsed):
        key_id = key["key_id"]
        secret = key["secret"]
        trust_store.register_key(key_id, secret.encode("utf-8"))
        if key.get("revoked"):
            trust_store.revoke_key(key_id)
    return C3ReportVerifier(trust_store)


def _verifier_key_items(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        if all(isinstance(secret, str) for secret in value.values()):
            return [{"key_id": str(key_id), "secret": secret} for key_id, secret in value.items()]
        keys = value.get("keys")
        if isinstance(keys, list):
            value = keys
    if not isinstance(value, list):
        raise RuntimeError("ARGUS_S8_C3_VERIFIER_KEYS_JSON must be an object map or a list of key objects")
    items: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            raise RuntimeError("verifier key entries must be objects")
        key_id = item.get("key_id")
        secret = item.get("secret")
        if not isinstance(key_id, str) or not key_id:
            raise RuntimeError("verifier key entry key_id is required")
        if not isinstance(secret, str) or not secret:
            raise RuntimeError("verifier key entry secret is required")
        items.append({"key_id": key_id, "secret": secret, "revoked": bool(item.get("revoked", False))})
    return items


def _rust_ledger_writer_from_env(
    env: dict[str, str],
    *,
    dsn: str,
    db_role: str | None,
) -> SubprocessRustLedgerWriter:
    command_text = env.get("ARGUS_S8_RUST_LEDGER_WRITER_CMD")
    if not command_text:
        raise RuntimeError("ARGUS_S8_RUST_LEDGER_WRITER_CMD is required")
    command = shlex.split(command_text)
    if not command:
        raise RuntimeError("ARGUS_S8_RUST_LEDGER_WRITER_CMD is empty")
    return SubprocessRustLedgerWriter(
        command=command,
        dsn=dsn,
        db_role=db_role,
        checkpoint_signer_url=_required_env(env, "ARGUS_S8_CHECKPOINT_SIGNER_URL"),
        checkpoint_signer_auth_token=_required_env(env, "ARGUS_S8_CHECKPOINT_SIGNER_AUTH_TOKEN"),
        allow_insecure_checkpoint_signer=_env_flag(env.get("ARGUS_S8_ALLOW_INSECURE_CHECKPOINT_SIGNER")),
    )


def _env_flag(value: str | None) -> bool:
    return value is not None and value.strip().lower() in {"1", "true", "yes", "on"}


def _checkpoint_signer_kind(url: str, *, allow_insecure_checkpoint_signer: bool) -> str:
    if url.startswith("http://"):
        if allow_insecure_checkpoint_signer:
            return "s10-http-insecure-local"
        raise RuntimeError(
            "ARGUS_S8_ALLOW_INSECURE_CHECKPOINT_SIGNER=1 is required for http:// checkpoint signer URLs"
        )
    if url.startswith("https://"):
        raise RuntimeError(
            "https:// checkpoint signer URLs require a TLS/mTLS-capable Rust ledger writer; "
            "the current writer only permits explicit local http:// overrides"
        )
    raise RuntimeError(
        "ARGUS_S8_CHECKPOINT_SIGNER_URL must use https://, or http:// only with "
        "ARGUS_S8_ALLOW_INSECURE_CHECKPOINT_SIGNER=1 for local M0"
    )


def _rust_ledger_draft(record: ArtifactRecord) -> dict[str, Any]:
    return {
        "artifact_id": record.artifact_ref,
        "content_hash": record.content_hash,
        "kind": record.kind,
        "producer": asdict(record.producer),
        "lineage": asdict(record.lineage),
        "record_hash": hash_json(asdict(record)),
        "merkle_seq": 0,
        "claim_tier": record.claim_tier,
        "validation_report_ref": record.validation_report_ref,
        "input_refs": list(record.lineage.input_refs),
        "created_at": record.created_at,
        "size_bytes": record.size_bytes,
    }


def _set_role(conn: Any, db_role: str | None) -> None:
    if not db_role:
        return
    from psycopg import sql

    with conn.cursor() as cur:
        cur.execute(sql.SQL("SET ROLE {};").format(sql.Identifier(db_role)))


def apply_s8_migrations(*, dsn: str, migrations_dir: Path) -> None:
    import psycopg

    migrations = sorted(migrations_dir.glob("*.sql"))
    if not migrations:
        raise RuntimeError(f"no S8 migrations found in {migrations_dir}")
    with psycopg.connect(dsn, autocommit=True) as conn:
        for migration in migrations:
            migration_id = migration.stem
            checksum = _sha256(migration)
            existing = _existing_checksum(conn, migration_id)
            if existing == checksum:
                continue
            if existing is not None:
                raise RuntimeError(
                    f"S8 migration checksum drift for {migration_id}: "
                    f"recorded={existing} current={checksum}"
                )
            with conn.cursor() as cur:
                cur.execute(migration.read_text())
                cur.execute(
                    """
                    INSERT INTO s8.schema_migration (migration_id, checksum_sha256)
                    VALUES (%s, %s)
                    ON CONFLICT (migration_id) DO NOTHING;
                    """,
                    (migration_id, checksum),
                )


def _existing_checksum(conn: Any, migration_id: str) -> str | None:
    with conn.cursor() as cur:
        try:
            cur.execute("SELECT to_regclass('s8.schema_migration') IS NOT NULL;")
            exists = bool(cur.fetchone()[0])
        except Exception:
            return None
        if not exists:
            return None
        cur.execute(
            "SELECT checksum_sha256 FROM s8.schema_migration WHERE migration_id = %s;",
            (migration_id,),
        )
        row = cur.fetchone()
        return str(row[0]) if row else None


def _record_from_row(row: dict[str, Any], *, size_bytes: int) -> ArtifactRecord:
    created_at = row["created_at"]
    if isinstance(created_at, datetime):
        created_at = created_at.astimezone(UTC).isoformat().replace("+00:00", "Z")
    lineage = dict(row["lineage"])
    lineage["input_refs"] = tuple(lineage.get("input_refs") or ())
    lineage["seeds"] = tuple(lineage.get("seeds") or ())
    return ArtifactRecord(
        artifact_ref=str(row["artifact_id"]),
        kind=str(row["kind"]),
        content_hash=str(row["content_hash"]),
        size_bytes=size_bytes,
        producer=Producer(**dict(row["producer"])),
        lineage=Lineage(**lineage),
        claim_tier=str(row["claim_tier"]),
        validation_report_ref=row["validation_report_ref"],
        created_at=str(created_at),
    )


def _required_env(env: dict[str, str], name: str) -> str:
    value = env.get(name)
    if not value:
        raise RuntimeError(f"{name} is required for S8 Postgres/MinIO persistence")
    return value


def _jsonb_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        parsed = json.loads(value)
        if isinstance(parsed, dict):
            return parsed
    raise TypeError(f"expected json object, got {type(value).__name__}")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
