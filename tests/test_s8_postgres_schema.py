from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
from tempfile import TemporaryDirectory
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_SQL = ROOT / "db" / "s8" / "001_append_only_schema.sql"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@unittest.skipUnless(
    shutil.which("initdb") and shutil.which("pg_ctl") and shutil.which("psql"),
    "PostgreSQL command-line tools are required for S8 schema tests",
)
class S8PostgresSchemaTests(unittest.TestCase):
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
        cls.preexisting_roles = set()

    @classmethod
    def _start_existing_postgres_database(cls) -> None:
        cls.uses_existing_postgres = True
        cls.pg_host = "127.0.0.1"
        cls.pg_port = None
        cls.pg_database = f"argus_s8_py_test_{os.getpid()}_{secrets.token_hex(4)}"
        roles = _run_checked(
            [
                "psql",
                "-X",
                "-q",
                "-t",
                "-A",
                "-h",
                cls.pg_host,
                "-d",
                "postgres",
                "-c",
                (
                    "SELECT rolname FROM pg_roles "
                    "WHERE rolname IN ('argus_s8_reader', 'argus_s8_ledger_writer') "
                    "ORDER BY rolname;"
                ),
            ]
        )
        cls.preexisting_roles = {line.strip() for line in roles.stdout.splitlines() if line.strip()}
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
            for role in ("argus_s8_ledger_writer", "argus_s8_reader"):
                if role not in cls.preexisting_roles:
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
                            f"DROP ROLE IF EXISTS {role};",
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
        self._psql("DROP SCHEMA IF EXISTS s8 CASCADE;")
        self._psql_file(SCHEMA_SQL)

    def test_ledger_writer_commits_records_and_lineage_through_function(self) -> None:
        self._commit_record("c4://artifact/a", sequence=1, kind="dataset")
        self._commit_record("c4://artifact/report", sequence=2, kind="validation_report")
        self._commit_record(
            "c4://artifact/b",
            sequence=3,
            kind="model",
            input_refs=["c4://artifact/a"],
            validation_report_ref="c4://artifact/report",
        )

        input_edge = self._psql(
            """
            SELECT count(*)
            FROM s8.lineage_closure
            WHERE ancestor_id = 'c4://artifact/a'
              AND descendant_id = 'c4://artifact/b'
              AND depth = 1;
            """
        )
        report_edge = self._psql(
            """
            SELECT count(*)
            FROM s8.lineage_closure
            WHERE ancestor_id = 'c4://artifact/report'
              AND descendant_id = 'c4://artifact/b'
              AND depth = 1;
            """
        )
        record_count = self._psql("SELECT count(*) FROM s8.artifact_record;")

        self.assertEqual(input_edge.stdout.strip(), "1")
        self.assertEqual(report_edge.stdout.strip(), "1")
        self.assertEqual(record_count.stdout.strip(), "3")

    def test_commit_function_is_idempotent_for_identical_record(self) -> None:
        first = self._commit_record("c4://artifact/a", sequence=1)
        second = self._commit_record("c4://artifact/a", sequence=1)

        result = self._psql("SELECT count(*) FROM s8.artifact_record WHERE artifact_id = 'c4://artifact/a';")

        self.assertEqual(first.stdout.strip(), "t")
        self.assertEqual(second.stdout.strip(), "f")
        self.assertEqual(result.stdout.strip(), "1")

    def test_commit_function_rejects_conflicting_artifact_ref(self) -> None:
        self._commit_record("c4://artifact/a", sequence=1)

        conflict = self._commit_record("c4://artifact/a", sequence=99, check=False)

        self.assertNotEqual(conflict.returncode, 0)
        self.assertIn("already exists with different payload", conflict.stderr)

    def test_commit_rolls_back_when_lineage_edge_fails(self) -> None:
        failed = self._commit_record(
            "c4://artifact/b",
            sequence=2,
            kind="model",
            input_refs=["c4://artifact/missing"],
            check=False,
        )
        record_count = self._psql("SELECT count(*) FROM s8.artifact_record WHERE artifact_id = 'c4://artifact/b';")
        edge_count = self._psql("SELECT count(*) FROM s8.lineage_edge;")

        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("violates foreign key constraint", failed.stderr)
        self.assertEqual(record_count.stdout.strip(), "0")
        self.assertEqual(edge_count.stdout.strip(), "0")

    def test_lineage_function_maintains_transitive_closure_and_rejects_cycles(self) -> None:
        self._commit_record("c4://artifact/a", sequence=1)
        self._commit_record("c4://artifact/b", sequence=2)
        self._commit_record("c4://artifact/c", sequence=3)
        self._psql(
            """
            SET ROLE argus_s8_ledger_writer;
            SELECT s8.insert_lineage_edge('c4://artifact/a', 'c4://artifact/b', 'input', NULL);
            SELECT s8.insert_lineage_edge('c4://artifact/b', 'c4://artifact/c', 'input', NULL);
            RESET ROLE;
            """
        )

        transitive = self._psql(
            """
            SELECT depth
            FROM s8.lineage_closure
            WHERE ancestor_id = 'c4://artifact/a'
              AND descendant_id = 'c4://artifact/c';
            """
        )
        cyclic = self._psql(
            """
            SET ROLE argus_s8_ledger_writer;
            SELECT s8.insert_lineage_edge('c4://artifact/c', 'c4://artifact/a', 'input', NULL);
            """,
            check=False,
        )

        self.assertEqual(transitive.stdout.strip(), "2")
        self.assertNotEqual(cyclic.returncode, 0)
        self.assertIn("lineage cycle detected", cyclic.stderr)

    def test_ledger_leaf_function_enforces_sequence_and_denies_direct_insert(self) -> None:
        zero_root = "blake3:" + ("0" * 64)
        first_root = "blake3:leaf-root-1"
        self._commit_record("c4://artifact/a", sequence=1)
        self._commit_record("c4://artifact/b", sequence=2)
        self._psql(
            f"""
            SET ROLE argus_s8_ledger_writer;
            SELECT s8.append_ledger_leaf(
                'c4://artifact/a',
                'blake3:record-1',
                1,
                '{zero_root}',
                '{first_root}'
            );
            RESET ROLE;
            """
        )
        wrong_sequence = self._psql(
            f"""
            SET ROLE argus_s8_ledger_writer;
            SELECT s8.append_ledger_leaf(
                'c4://artifact/b',
                'blake3:record-2',
                3,
                '{first_root}',
                'blake3:leaf-root-2'
            );
            """,
            check=False,
        )
        direct_leaf = self._psql(
            f"""
            SET ROLE argus_s8_ledger_writer;
            INSERT INTO s8.ledger_leaf (sequence, artifact_id, record_hash, previous_root, root)
            VALUES (2, 'c4://artifact/b', 'blake3:record-2', '{first_root}', 'blake3:leaf-root-2');
            """,
            check=False,
        )
        leaf_count = self._psql("SELECT count(*) FROM s8.ledger_leaf;")

        self.assertNotEqual(wrong_sequence.returncode, 0)
        self.assertIn("ledger sequence mismatch", wrong_sequence.stderr)
        self.assertNotEqual(direct_leaf.returncode, 0)
        self.assertIn("permission denied", direct_leaf.stderr)
        self.assertEqual(leaf_count.stdout.strip(), "1")

    def test_writer_role_cannot_bypass_lineage_function(self) -> None:
        self._commit_record("c4://artifact/a", sequence=1)
        self._commit_record("c4://artifact/b", sequence=2)
        direct_record = self._psql(
            """
            SET ROLE argus_s8_ledger_writer;
            INSERT INTO s8.artifact_record (
                artifact_id, content_hash, kind, producer, lineage, record_hash, merkle_seq
            ) VALUES (
                'c4://artifact/direct', 'blake3:direct', 'dataset', '{}', '{}', 'blake3:direct-record', 9
            );
            """,
            check=False,
        )
        direct_edge = self._psql(
            """
            SET ROLE argus_s8_ledger_writer;
            INSERT INTO s8.lineage_edge (src_artifact_id, dst_artifact_id, edge_type)
            VALUES ('c4://artifact/a', 'c4://artifact/b', 'input');
            """,
            check=False,
        )
        direct_closure = self._psql(
            """
            SET ROLE argus_s8_ledger_writer;
            INSERT INTO s8.lineage_closure (ancestor_id, descendant_id, depth)
            VALUES ('c4://artifact/a', 'c4://artifact/b', 1);
            """,
            check=False,
        )

        self.assertNotEqual(direct_record.returncode, 0)
        self.assertIn("permission denied", direct_record.stderr)
        self.assertNotEqual(direct_edge.returncode, 0)
        self.assertIn("permission denied", direct_edge.stderr)
        self.assertNotEqual(direct_closure.returncode, 0)
        self.assertIn("permission denied", direct_closure.stderr)

    def test_update_and_delete_are_rejected_even_for_owner(self) -> None:
        self._commit_record("c4://artifact/a", sequence=1)

        update = self._psql(
            "UPDATE s8.artifact_record SET kind = 'tampered' WHERE artifact_id = 'c4://artifact/a';",
            check=False,
        )
        delete = self._psql("DELETE FROM s8.artifact_record WHERE artifact_id = 'c4://artifact/a';", check=False)

        self.assertNotEqual(update.returncode, 0)
        self.assertIn("append-only table artifact_record", update.stderr)
        self.assertNotEqual(delete.returncode, 0)
        self.assertIn("append-only table artifact_record", delete.stderr)

    def test_reader_role_cannot_insert(self) -> None:
        denied = self._psql(
            """
            SET ROLE argus_s8_reader;
            INSERT INTO s8.artifact_record (
                artifact_id, content_hash, kind, producer, lineage, record_hash, merkle_seq
            ) VALUES (
                'c4://artifact/reader', 'blake3:reader', 'dataset', '{}', '{}', 'blake3:reader-record', 9
            );
            """,
            check=False,
        )
        commit_denied = self._psql(
            """
            SET ROLE argus_s8_reader;
            SELECT s8.commit_artifact_record(
                'c4://artifact/reader-commit',
                'blake3:reader-commit',
                'dataset',
                '{}'::jsonb,
                '{}'::jsonb,
                'blake3:reader-commit-record',
                10
            );
            """,
            check=False,
        )

        self.assertNotEqual(denied.returncode, 0)
        self.assertIn("permission denied", denied.stderr)
        self.assertNotEqual(commit_denied.returncode, 0)
        self.assertIn("permission denied", commit_denied.stderr)

    def _commit_record(
        self,
        artifact_ref: str,
        *,
        sequence: int,
        kind: str = "dataset",
        input_refs: list[str] | None = None,
        validation_report_ref: str | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        input_refs = input_refs or []
        producer = {"subsystem": "S6", "version": "1"}
        lineage = {
            "input_refs": input_refs,
            "code_ref": f"git:{sequence}",
            "environment_digest": f"oci:{sequence}",
        }
        validation_ref_sql = "NULL"
        if validation_report_ref is not None:
            validation_ref_sql = _sql_literal(validation_report_ref)

        return self._psql(
            f"""
            SET ROLE argus_s8_ledger_writer;
            SELECT s8.commit_artifact_record(
                {_sql_literal(artifact_ref)},
                {_sql_literal(f"blake3:{sequence}")},
                {_sql_literal(kind)},
                {_jsonb_literal(producer)},
                {_jsonb_literal(lineage)},
                {_sql_literal(f"blake3:record-{sequence}")},
                {sequence},
                'ran-toy',
                {validation_ref_sql},
                {_text_array_literal(input_refs)}
            );
            """,
            check=check,
        )

    def _psql_file(self, path: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self._psql_base() + ["-f", str(path)],
            check=True,
            text=True,
            capture_output=True,
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
        command.extend(
            [
                "-d",
                self.pg_database,
            ]
        )
        return command


def _sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _jsonb_literal(value: object) -> str:
    payload = json.dumps(value, separators=(",", ":"), sort_keys=True)
    return f"{_sql_literal(payload)}::jsonb"


def _text_array_literal(values: list[str]) -> str:
    if not values:
        return "ARRAY[]::text[]"
    return "ARRAY[" + ", ".join(_sql_literal(value) for value in values) + "]::text[]"


def _run_checked(args: list[str]) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, check=False, text=True, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(
            "command failed: "
            + " ".join(args)
            + "\nstdout:\n"
            + result.stdout
            + "\nstderr:\n"
            + result.stderr
        )
    return result


if __name__ == "__main__":
    unittest.main()
