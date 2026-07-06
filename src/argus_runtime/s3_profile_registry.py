"""Runtime persistence backend for the S3 VerifierProfile registry."""

from __future__ import annotations

from typing import Any, Mapping

from argus_core import (
    VerifierProfileRegistryError,
    VerifierProfileRevision,
    VerifierProfileStatusEvent,
)
from argus_core.s3 import build_verifier_profile_revision


class PostgresVerifierProfileRegistry:
    """Append-only S3 VerifierProfile registry backed by PostgreSQL."""

    def __init__(self, *, dsn: str, db_role: str | None = None) -> None:
        self._dsn = dsn
        self._db_role = db_role

    def publish(self, spec: Mapping[str, Any], *, actor: str = "s3-profile-registry") -> VerifierProfileRevision:
        import psycopg
        from psycopg.types.json import Jsonb

        if not isinstance(spec, Mapping):
            raise VerifierProfileRegistryError(
                code="S3_PROFILE_JSON_INVALID",
                message="VerifierProfile must be a JSON object",
            )
        profile_id = spec.get("profile_id")
        if not isinstance(profile_id, str) or not profile_id:
            raise VerifierProfileRegistryError(
                code="S3_PROFILE_FIELD_REQUIRED",
                message="profile_id must be a non-empty string",
            )

        with psycopg.connect(self._dsn) as conn:
            _set_role(conn, self._db_role)
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT pg_advisory_xact_lock(hashtext(%s));",
                        (f"s3.verifier_profile:{profile_id}",),
                    )
                    cur.execute(
                        """
                        SELECT COALESCE(max(revision), 0) + 1
                        FROM s3.verifier_profile_revision
                        WHERE profile_id = %s;
                        """,
                        (profile_id,),
                    )
                    revision = int(cur.fetchone()[0])
                    profile = build_verifier_profile_revision(spec, revision=revision, status="active")
                    cur.execute(
                        """
                        INSERT INTO s3.verifier_profile_revision (
                            profile_id,
                            revision,
                            profile_ref,
                            subtopic,
                            checks,
                            cost_estimate,
                            spec_json,
                            spec_hash,
                            published_by
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);
                        """,
                        (
                            profile.profile_id,
                            profile.revision,
                            profile.profile_ref,
                            profile.subtopic,
                            list(profile.checks),
                            Jsonb(profile.cost_estimate),
                            Jsonb(profile.spec_json),
                            profile.spec_hash,
                            actor,
                        ),
                    )
                    cur.execute(
                        """
                        INSERT INTO s3.verifier_profile_status_event (
                            profile_id,
                            revision,
                            status,
                            reason,
                            actor
                        )
                        VALUES (%s, %s, 'active', 'published', %s);
                        """,
                        (profile.profile_id, profile.revision, actor),
                    )
        return self.get(profile_id=profile.profile_id, revision=profile.revision)

    def get(self, *, profile_id: str, revision: int) -> VerifierProfileRevision:
        row = self._fetch_profile(
            """
            SELECT *
            FROM s3.verifier_profile_revision
            WHERE profile_id = %s AND revision = %s;
            """,
            (profile_id, revision),
        )
        return self._profile_from_row(row)

    def get_by_ref(self, profile_ref: str) -> VerifierProfileRevision:
        row = self._fetch_profile(
            """
            SELECT *
            FROM s3.verifier_profile_revision
            WHERE profile_ref = %s;
            """,
            (profile_ref,),
        )
        return self._profile_from_row(row)

    def latest(self, profile_id: str) -> VerifierProfileRevision:
        row = self._fetch_profile(
            """
            SELECT *
            FROM s3.verifier_profile_revision
            WHERE profile_id = %s
            ORDER BY revision DESC
            LIMIT 1;
            """,
            (profile_id,),
        )
        return self._profile_from_row(row)

    def list_profiles(self, *, subtopic: str | None = None, include_revoked: bool = False) -> tuple[VerifierProfileRevision, ...]:
        import psycopg
        from psycopg.rows import dict_row

        where = []
        params: list[Any] = []
        if subtopic is not None:
            where.append("r.subtopic = %s")
            params.append(subtopic)
        where_clause = "WHERE " + " AND ".join(where) if where else ""
        query = f"""
            SELECT r.*
            FROM s3.verifier_profile_revision r
            {where_clause}
            ORDER BY r.profile_id, r.revision;
        """
        with psycopg.connect(self._dsn, row_factory=dict_row) as conn:
            _set_role(conn, self._db_role)
            with conn.cursor() as cur:
                cur.execute(query, tuple(params))
                profiles = tuple(self._profile_from_row(row) for row in cur.fetchall())
        if include_revoked:
            return profiles
        return tuple(profile for profile in profiles if profile.status != "revoked")

    def deprecate(
        self,
        *,
        profile_id: str,
        revision: int,
        reason: str,
        actor: str = "s3-profile-registry",
    ) -> VerifierProfileRevision:
        return self._append_status(profile_id=profile_id, revision=revision, status="deprecated", reason=reason, actor=actor)

    def revoke(
        self,
        *,
        profile_id: str,
        revision: int,
        reason: str,
        actor: str = "s3-profile-registry",
    ) -> VerifierProfileRevision:
        return self._append_status(profile_id=profile_id, revision=revision, status="revoked", reason=reason, actor=actor)

    def status_events(
        self,
        *,
        profile_id: str | None = None,
        revision: int | None = None,
    ) -> tuple[VerifierProfileStatusEvent, ...]:
        import psycopg
        from psycopg.rows import dict_row

        where = []
        params: list[Any] = []
        if profile_id is not None:
            where.append("profile_id = %s")
            params.append(profile_id)
        if revision is not None:
            where.append("revision = %s")
            params.append(revision)
        where_clause = "WHERE " + " AND ".join(where) if where else ""
        query = f"""
            SELECT profile_id, revision, status, reason, actor
            FROM s3.verifier_profile_status_event
            {where_clause}
            ORDER BY event_id;
        """
        with psycopg.connect(self._dsn, row_factory=dict_row) as conn:
            _set_role(conn, self._db_role)
            with conn.cursor() as cur:
                cur.execute(query, tuple(params))
                return tuple(
                    VerifierProfileStatusEvent(
                        profile_id=str(row["profile_id"]),
                        revision=int(row["revision"]),
                        status=str(row["status"]),
                        reason=str(row["reason"]),
                        actor=str(row["actor"]),
                    )
                    for row in cur.fetchall()
                )

    def _append_status(
        self,
        *,
        profile_id: str,
        revision: int,
        status: str,
        reason: str,
        actor: str,
    ) -> VerifierProfileRevision:
        import psycopg

        if not reason:
            raise VerifierProfileRegistryError(
                code="S3_PROFILE_STATUS_REASON_REQUIRED",
                message="profile status event requires a reason",
            )
        self.get(profile_id=profile_id, revision=revision)
        with psycopg.connect(self._dsn) as conn:
            _set_role(conn, self._db_role)
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO s3.verifier_profile_status_event (
                            profile_id,
                            revision,
                            status,
                            reason,
                            actor
                        )
                        VALUES (%s, %s, %s, %s, %s);
                        """,
                        (profile_id, revision, status, reason, actor),
                    )
        return self.get(profile_id=profile_id, revision=revision)

    def _fetch_profile(self, query: str, params: tuple[Any, ...]) -> dict[str, Any]:
        import psycopg
        from psycopg.rows import dict_row

        with psycopg.connect(self._dsn, row_factory=dict_row) as conn:
            _set_role(conn, self._db_role)
            with conn.cursor() as cur:
                cur.execute(query, params)
                row = cur.fetchone()
        if row is None:
            raise VerifierProfileRegistryError(
                code="S3_PROFILE_NOT_FOUND",
                message="VerifierProfile revision was not found",
            )
        return dict(row)

    def _profile_from_row(self, row: Mapping[str, Any]) -> VerifierProfileRevision:
        status = self._latest_status(profile_id=str(row["profile_id"]), revision=int(row["revision"]))
        profile = build_verifier_profile_revision(row["spec_json"], revision=int(row["revision"]), status=status)
        if profile.spec_hash != row["spec_hash"]:
            raise VerifierProfileRegistryError(
                code="S3_PROFILE_SPEC_HASH_MISMATCH",
                message="stored profile spec_hash does not match canonical spec_json",
            )
        return profile

    def _latest_status(self, *, profile_id: str, revision: int) -> str:
        import psycopg

        with psycopg.connect(self._dsn) as conn:
            _set_role(conn, self._db_role)
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT status
                    FROM s3.verifier_profile_status_event
                    WHERE profile_id = %s AND revision = %s
                    ORDER BY event_id DESC
                    LIMIT 1;
                    """,
                    (profile_id, revision),
                )
                row = cur.fetchone()
        return str(row[0]) if row is not None else "active"


def _set_role(conn: Any, db_role: str | None) -> None:
    if not db_role:
        return
    from psycopg import sql

    with conn.cursor() as cur:
        cur.execute(sql.SQL("SET ROLE {};").format(sql.Identifier(db_role)))
