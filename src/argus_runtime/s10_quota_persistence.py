"""Durable S10 quota ledger backed by PostgreSQL."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
from pathlib import Path
from typing import Any

from argus_core import BudgetCaps, BudgetExceededError, BudgetToken, BudgetUsage, InMemoryQuotaLedger, QuotaState


DEFAULT_S10_MIGRATIONS_DIR = Path(__file__).resolve().parents[2] / "db" / "s10"


class PostgresQuotaLedger:
    """PostgreSQL system-of-record for S10 reserve/consume/release accounting."""

    kind = "postgres"

    def __init__(self, *, dsn: str) -> None:
        self._dsn = dsn

    def register_budget(self, token: BudgetToken) -> None:
        import psycopg
        from psycopg.types.json import Jsonb

        caps = _caps_to_json(token.caps)
        empty_usage = _usage_to_json(BudgetUsage())
        with psycopg.connect(self._dsn) as conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO s10.quota_budget (
                            budget_id,
                            job_id,
                            root_request_id,
                            risk_class,
                            budget_epoch,
                            caps,
                            reserved,
                            actual,
                            halted
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, false)
                        ON CONFLICT (budget_id) DO NOTHING
                        RETURNING budget_id;
                        """,
                        (
                            token.budget_id,
                            token.job_id,
                            token.root_request_id,
                            token.risk_class,
                            token.budget_epoch,
                            Jsonb(caps),
                            Jsonb(empty_usage),
                            Jsonb(empty_usage),
                        ),
                    )
                    if cur.fetchone() is not None:
                        state = QuotaState(caps=token.caps, reserved=BudgetUsage(), actual=BudgetUsage())
                        self._insert_entry(cur, token.budget_id, "register", BudgetUsage(), state)

    def reserve(self, budget_id: str, usage: BudgetUsage) -> None:
        _assert_non_negative_usage(usage)
        import psycopg
        from psycopg.types.json import Jsonb

        with psycopg.connect(self._dsn) as conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    state = self._fetch_state(cur, budget_id, lock=True)
                    InMemoryQuotaLedger._assert_not_halted(budget_id, state)
                    next_reserved = InMemoryQuotaLedger._add_usage(state.reserved, usage)
                    InMemoryQuotaLedger._assert_within_caps(state.caps, next_reserved, state.actual, budget_id)
                    next_state = QuotaState(
                        caps=state.caps,
                        reserved=next_reserved,
                        actual=state.actual,
                        halted=state.halted,
                    )
                    cur.execute(
                        """
                        UPDATE s10.quota_budget
                        SET reserved = %s, updated_at = now()
                        WHERE budget_id = %s;
                        """,
                        (Jsonb(_usage_to_json(next_reserved)), budget_id),
                    )
                    self._insert_entry(cur, budget_id, "reserve", usage, next_state)

    def consume(self, budget_id: str, usage: BudgetUsage) -> None:
        _assert_non_negative_usage(usage)
        import psycopg
        from psycopg.types.json import Jsonb

        exceeded_error: BudgetExceededError | None = None
        with psycopg.connect(self._dsn) as conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    state = self._fetch_state(cur, budget_id, lock=True)
                    InMemoryQuotaLedger._assert_not_halted(budget_id, state)
                    next_actual = InMemoryQuotaLedger._add_usage(state.actual, usage)
                    next_state = QuotaState(
                        caps=state.caps,
                        reserved=state.reserved,
                        actual=next_actual,
                        halted=False,
                    )
                    try:
                        InMemoryQuotaLedger._assert_actual_within_caps(state.caps, next_actual)
                    except BudgetExceededError:
                        halted_state = QuotaState(
                            caps=state.caps,
                            reserved=state.reserved,
                            actual=next_actual,
                            halted=True,
                        )
                        cur.execute(
                            """
                            UPDATE s10.quota_budget
                            SET actual = %s, halted = true, updated_at = now()
                            WHERE budget_id = %s;
                            """,
                            (Jsonb(_usage_to_json(next_actual)), budget_id),
                        )
                        self._insert_entry(cur, budget_id, "halt", usage, halted_state)
                        exceeded_error = BudgetExceededError(f"budget exceeded for {budget_id}")
                    else:
                        cur.execute(
                            """
                            UPDATE s10.quota_budget
                            SET actual = %s, updated_at = now()
                            WHERE budget_id = %s;
                            """,
                            (Jsonb(_usage_to_json(next_actual)), budget_id),
                        )
                        self._insert_entry(cur, budget_id, "consume", usage, next_state)
        if exceeded_error is not None:
            raise exceeded_error

    def release(self, budget_id: str, usage: BudgetUsage | None = None) -> None:
        import psycopg
        from psycopg.types.json import Jsonb

        with psycopg.connect(self._dsn) as conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    state = self._fetch_state(cur, budget_id, lock=True)
                    released = usage or state.reserved
                    _assert_non_negative_usage(released)
                    next_reserved = InMemoryQuotaLedger._subtract_usage(state.reserved, released)
                    next_state = QuotaState(
                        caps=state.caps,
                        reserved=next_reserved,
                        actual=state.actual,
                        halted=state.halted,
                    )
                    cur.execute(
                        """
                        UPDATE s10.quota_budget
                        SET reserved = %s, updated_at = now()
                        WHERE budget_id = %s;
                        """,
                        (Jsonb(_usage_to_json(next_reserved)), budget_id),
                    )
                    self._insert_entry(cur, budget_id, "release", released, next_state)

    def remaining(self, budget_id: str) -> BudgetUsage:
        state = self.state(budget_id)
        return _remaining(state)

    def state(self, budget_id: str) -> QuotaState:
        import psycopg

        with psycopg.connect(self._dsn) as conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    return self._fetch_state(cur, budget_id, lock=False)

    def _fetch_state(self, cur: Any, budget_id: str, *, lock: bool) -> QuotaState:
        suffix = " FOR UPDATE" if lock else ""
        cur.execute(
            f"""
            SELECT caps, reserved, actual, halted
            FROM s10.quota_budget
            WHERE budget_id = %s{suffix};
            """,
            (budget_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise KeyError(f"unknown budget_id: {budget_id}")
        return QuotaState(
            caps=_caps_from_json(row[0]),
            reserved=_usage_from_json(row[1]),
            actual=_usage_from_json(row[2]),
            halted=bool(row[3]),
        )

    def _insert_entry(
        self,
        cur: Any,
        budget_id: str,
        entry_type: str,
        delta: BudgetUsage,
        state: QuotaState,
    ) -> None:
        from psycopg.types.json import Jsonb

        cur.execute(
            """
            INSERT INTO s10.quota_ledger_entry (
                budget_id,
                entry_type,
                delta,
                reserved_after,
                actual_after,
                remaining_after,
                halted_after
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s);
            """,
            (
                budget_id,
                entry_type,
                Jsonb(_usage_to_json(delta)),
                Jsonb(_usage_to_json(state.reserved)),
                Jsonb(_usage_to_json(state.actual)),
                Jsonb(_usage_to_json(_remaining(state))),
                state.halted,
            ),
        )


def build_postgres_quota_ledger_from_env(env: dict[str, str]) -> PostgresQuotaLedger:
    dsn = env.get("ARGUS_S10_QUOTA_POSTGRES_DSN")
    if not dsn:
        raise RuntimeError("ARGUS_S10_QUOTA_POSTGRES_DSN is required")
    if env.get("ARGUS_S10_APPLY_MIGRATIONS") == "1":
        migrations_dir = Path(env.get("ARGUS_S10_MIGRATIONS_DIR", str(DEFAULT_S10_MIGRATIONS_DIR)))
        apply_s10_migrations(dsn=dsn, migrations_dir=migrations_dir)
    return PostgresQuotaLedger(dsn=dsn)


def apply_s10_migrations(*, dsn: str, migrations_dir: Path) -> None:
    import psycopg

    migrations = sorted(migrations_dir.glob("*.sql"))
    if not migrations:
        raise RuntimeError(f"no S10 migrations found in {migrations_dir}")
    with psycopg.connect(dsn, autocommit=True) as conn:
        for migration in migrations:
            migration_id = migration.stem
            checksum = _sha256(migration)
            existing = _existing_checksum(conn, migration_id)
            if existing == checksum:
                continue
            if existing is not None:
                raise RuntimeError(
                    f"S10 migration checksum drift for {migration_id}: "
                    f"recorded={existing} current={checksum}"
                )
            with conn.cursor() as cur:
                cur.execute(migration.read_text())
                cur.execute(
                    """
                    INSERT INTO s10.schema_migration (migration_id, checksum_sha256)
                    VALUES (%s, %s)
                    ON CONFLICT (migration_id) DO NOTHING;
                    """,
                    (migration_id, checksum),
                )


def _existing_checksum(conn: Any, migration_id: str) -> str | None:
    with conn.cursor() as cur:
        try:
            cur.execute("SELECT to_regclass('s10.schema_migration') IS NOT NULL;")
            exists = bool(cur.fetchone()[0])
        except Exception:
            return None
        if not exists:
            return None
        cur.execute(
            "SELECT checksum_sha256 FROM s10.schema_migration WHERE migration_id = %s;",
            (migration_id,),
        )
        row = cur.fetchone()
        return str(row[0]) if row else None


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _remaining(state: QuotaState) -> BudgetUsage:
    return InMemoryQuotaLedger._subtract_usage(
        InMemoryQuotaLedger._caps_to_usage(state.caps),
        InMemoryQuotaLedger._add_usage(state.reserved, state.actual),
    )


def _usage_to_json(usage: BudgetUsage) -> dict[str, float]:
    return {field: float(value) for field, value in asdict(usage).items()}


def _usage_from_json(value: Any) -> BudgetUsage:
    data = dict(value or {})
    return BudgetUsage(**{field: float(data.get(field, 0.0)) for field in asdict(BudgetUsage())})


def _caps_to_json(caps: BudgetCaps) -> dict[str, float]:
    return {field: float(value) for field, value in asdict(caps).items()}


def _caps_from_json(value: Any) -> BudgetCaps:
    data = dict(value or {})
    return BudgetCaps(**{field: float(data.get(field, 0.0)) for field in asdict(BudgetCaps())})


def _assert_non_negative_usage(usage: BudgetUsage) -> None:
    for field, value in asdict(usage).items():
        if value < 0:
            raise BudgetExceededError(f"negative budget dimension: {field}")
