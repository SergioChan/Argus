from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
from tempfile import TemporaryDirectory
import unittest

from argus_core import BudgetCaps, BudgetExceededError, BudgetUsage, InMemoryTokenService
from argus_runtime.s10_quota_persistence import PostgresQuotaLedger, apply_s10_migrations


ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS_DIR = ROOT / "db" / "s10"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@unittest.skipUnless(
    shutil.which("initdb") and shutil.which("pg_ctl") and shutil.which("psql"),
    "PostgreSQL command-line tools are required for S10 quota tests",
)
class S10PostgresQuotaLedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tempdir = TemporaryDirectory()
        cls.root = Path(cls.tempdir.name)
        cls.data_dir = cls.root / "pgdata"
        cls.socket_dir = cls.root / "socket"
        cls.socket_dir.mkdir()
        cls.port = _free_port()
        try:
            _run_checked(["initdb", "-A", "trust", "--nosync", "-D", str(cls.data_dir)])
        except RuntimeError as exc:
            cls.tempdir.cleanup()
            if "could not create shared memory segment" in str(exc):
                cls._start_existing_postgres_database()
                return
            raise
        _run_checked(
            [
                "pg_ctl",
                "-D",
                str(cls.data_dir),
                "-l",
                str(cls.root / "postgres.log"),
                "-o",
                f"-k {cls.socket_dir} -p {cls.port} -c listen_addresses=''",
                "-w",
                "start",
            ]
        )
        cls.pg_host = str(cls.socket_dir)
        cls.pg_port = cls.port
        cls.pg_database = "postgres"
        cls.uses_existing_postgres = False

    @classmethod
    def _start_existing_postgres_database(cls) -> None:
        cls.uses_existing_postgres = True
        cls.pg_host = "127.0.0.1"
        cls.pg_port = None
        cls.pg_database = f"argus_s10_quota_test_{os.getpid()}_{secrets.token_hex(4)}"
        _run_checked(
            [
                "psql",
                "-X",
                "-q",
                "-h",
                cls.pg_host,
                "-d",
                "postgres",
                "-c",
                f"CREATE DATABASE {cls.pg_database};",
            ]
        )

    @classmethod
    def tearDownClass(cls) -> None:
        if getattr(cls, "uses_existing_postgres", False):
            _run_checked(
                [
                    "psql",
                    "-X",
                    "-q",
                    "-h",
                    cls.pg_host,
                    "-d",
                    "postgres",
                    "-c",
                    f"DROP DATABASE IF EXISTS {cls.pg_database};",
                ]
            )
        else:
            subprocess.run(
                ["pg_ctl", "-D", str(cls.data_dir), "-m", "fast", "-w", "stop"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            cls.tempdir.cleanup()

    def setUp(self) -> None:
        self._psql("DROP SCHEMA IF EXISTS s10 CASCADE;")
        apply_s10_migrations(dsn=self._postgres_dsn(), migrations_dir=MIGRATIONS_DIR)
        self.tokens = InMemoryTokenService(signing_key=b"quota-test", now_fn=lambda: 1_000)

    def test_postgres_quota_ledger_persists_reserve_consume_release_state(self) -> None:
        token = self.tokens.mint_budget(
            caps=BudgetCaps(max_gpu_seconds=100, max_cost_usd=100),
            job_id="job-1",
            root_request_id="root-1",
        )
        ledger = PostgresQuotaLedger(dsn=self._postgres_dsn())
        ledger.register_budget(token)
        ledger.reserve(token.budget_id, BudgetUsage(gpu_seconds=60, cost_usd=30))
        ledger.consume(token.budget_id, BudgetUsage(gpu_seconds=40, cost_usd=18))
        ledger.release(token.budget_id)

        reloaded = PostgresQuotaLedger(dsn=self._postgres_dsn())
        state = reloaded.state(token.budget_id)
        remaining = reloaded.remaining(token.budget_id)

        self.assertEqual(state.reserved, BudgetUsage())
        self.assertEqual(state.actual.gpu_seconds, 40)
        self.assertEqual(state.actual.cost_usd, 18)
        self.assertEqual(remaining.gpu_seconds, 60)
        self.assertEqual(remaining.cost_usd, 82)
        self.assertEqual(
            self._psql("SELECT string_agg(entry_type, ',' ORDER BY sequence) FROM s10.quota_ledger_entry;").stdout.strip(),
            "register,reserve,consume,release",
        )

    def test_concurrent_reservations_cannot_drive_remaining_negative(self) -> None:
        token = self.tokens.mint_budget(
            caps=BudgetCaps(max_gpu_seconds=10),
            job_id="job-concurrent",
            root_request_id="root-concurrent",
        )
        PostgresQuotaLedger(dsn=self._postgres_dsn()).register_budget(token)

        def reserve_one(_: int) -> bool:
            ledger = PostgresQuotaLedger(dsn=self._postgres_dsn())
            try:
                ledger.reserve(token.budget_id, BudgetUsage(gpu_seconds=1))
                return True
            except BudgetExceededError:
                return False

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(reserve_one, range(20)))

        ledger = PostgresQuotaLedger(dsn=self._postgres_dsn())
        state = ledger.state(token.budget_id)
        remaining = ledger.remaining(token.budget_id)

        self.assertEqual(sum(results), 10)
        self.assertEqual(state.reserved.gpu_seconds, 10)
        self.assertEqual(remaining.gpu_seconds, 0)
        self.assertGreaterEqual(remaining.cost_usd, 0)
        self.assertEqual(
            self._psql("SELECT count(*) FROM s10.quota_ledger_entry WHERE entry_type = 'reserve';").stdout.strip(),
            "10",
        )

    def test_over_budget_consume_persists_halt_and_refuses_future_reserve(self) -> None:
        token = self.tokens.mint_budget(
            caps=BudgetCaps(max_wallclock_s=10),
            job_id="job-halt",
            root_request_id="root-halt",
        )
        ledger = PostgresQuotaLedger(dsn=self._postgres_dsn())
        ledger.register_budget(token)

        with self.assertRaises(BudgetExceededError):
            ledger.consume(token.budget_id, BudgetUsage(wallclock_s=11))

        state = PostgresQuotaLedger(dsn=self._postgres_dsn()).state(token.budget_id)
        self.assertTrue(state.halted)
        self.assertEqual(state.actual.wallclock_s, 11)
        self.assertEqual(
            self._psql("SELECT entry_type FROM s10.quota_ledger_entry ORDER BY sequence DESC LIMIT 1;").stdout.strip(),
            "halt",
        )
        with self.assertRaisesRegex(BudgetExceededError, "budget is halted"):
            ledger.reserve(token.budget_id, BudgetUsage(wallclock_s=1))

    def test_explicit_halt_is_durable_without_debiting_above_the_cap(self) -> None:
        token = self.tokens.mint_budget(
            caps=BudgetCaps(max_model_tokens=1000, max_cost_usd=1),
            job_id="job-model-halt",
            root_request_id="root-model-halt",
        )
        ledger = PostgresQuotaLedger(dsn=self._postgres_dsn())
        ledger.register_budget(token)
        ledger.consume(token.budget_id, BudgetUsage(model_tokens=12, cost_usd=0.003))

        ledger.halt(token.budget_id, reason="model_reservation_exceeded")

        state = PostgresQuotaLedger(dsn=self._postgres_dsn()).state(token.budget_id)
        self.assertTrue(state.halted)
        self.assertEqual(state.actual, BudgetUsage(model_tokens=12, cost_usd=0.003))
        self.assertEqual(
            self._psql("SELECT entry_type FROM s10.quota_ledger_entry ORDER BY sequence DESC LIMIT 1;").stdout.strip(),
            "halt",
        )
        with self.assertRaisesRegex(BudgetExceededError, "budget is halted"):
            ledger.reserve(token.budget_id, BudgetUsage(model_tokens=1))

    def test_quota_ledger_entries_are_db_append_only_even_for_owner(self) -> None:
        token = self.tokens.mint_budget(
            caps=BudgetCaps(max_gpu_seconds=100),
            job_id="job-append-only",
            root_request_id="root-append-only",
        )
        ledger = PostgresQuotaLedger(dsn=self._postgres_dsn())
        ledger.register_budget(token)
        ledger.reserve(token.budget_id, BudgetUsage(gpu_seconds=1))

        update = self._psql(
            f"""
            UPDATE s10.quota_ledger_entry
            SET entry_type = 'consume'
            WHERE budget_id = '{token.budget_id}';
            """,
            check=False,
        )
        delete = self._psql(
            f"""
            DELETE FROM s10.quota_ledger_entry
            WHERE budget_id = '{token.budget_id}';
            """,
            check=False,
        )
        truncate = self._psql("TRUNCATE s10.quota_ledger_entry;", check=False)

        self.assertNotEqual(update.returncode, 0)
        self.assertIn("append-only table quota_ledger_entry", update.stderr)
        self.assertNotEqual(delete.returncode, 0)
        self.assertIn("append-only table quota_ledger_entry", delete.stderr)
        self.assertNotEqual(truncate.returncode, 0)
        self.assertIn("append-only table quota_ledger_entry", truncate.stderr)
        self.assertEqual(
            self._psql("SELECT string_agg(entry_type, ',' ORDER BY sequence) FROM s10.quota_ledger_entry;").stdout.strip(),
            "register,reserve",
        )

    def _psql(self, sql: str, *, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self._psql_base() + ["-c", sql],
            check=check,
            text=True,
            capture_output=True,
        )

    def _psql_base(self) -> list[str]:
        command = [
            "psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-X",
            "-q",
            "-t",
            "-A",
            "-h",
            str(self.pg_host),
        ]
        if self.pg_port is not None:
            command.extend(["-p", str(self.pg_port)])
        command.extend(["-d", self.pg_database])
        return command

    def _postgres_dsn(self) -> str:
        from psycopg.conninfo import make_conninfo

        kwargs = {"host": str(self.pg_host), "dbname": self.pg_database}
        if self.pg_port is not None:
            kwargs["port"] = str(self.pg_port)
        return make_conninfo("", **kwargs)


def _run_checked(command: list[str]) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, check=False, text=True, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(
            "command failed: "
            + " ".join(command)
            + "\nstdout:\n"
            + result.stdout
            + "\nstderr:\n"
            + result.stderr
        )
    return result


if __name__ == "__main__":
    unittest.main()
