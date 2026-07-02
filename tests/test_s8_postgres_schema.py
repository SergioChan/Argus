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
MIGRATIONS_DIR = ROOT / "db" / "s8"
MIGRATION_SCRIPT = ROOT / "scripts" / "apply_s8_migrations.py"


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
        self._apply_s8_migrations()

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

    def test_lineage_query_functions_match_closure_recursive_and_impact_set(self) -> None:
        self._commit_record("c4://artifact/source", sequence=1, kind="external_source")
        self._commit_record(
            "c4://artifact/dataset",
            sequence=2,
            kind="dataset",
            input_refs=["c4://artifact/source"],
        )
        self._commit_record("c4://artifact/report", sequence=3, kind="validation_report")
        self._commit_record(
            "c4://artifact/model",
            sequence=4,
            kind="model",
            input_refs=["c4://artifact/dataset"],
            validation_report_ref="c4://artifact/report",
        )
        self._commit_record("c4://artifact/child", sequence=5, kind="model")
        self._psql(
            """
            SET ROLE argus_s8_ledger_writer;
            SELECT s8.insert_lineage_edge(
                'c4://artifact/model',
                'c4://artifact/child',
                'derived_from',
                NULL
            );
            RESET ROLE;
            """
        )

        closure_ancestors = _stdout_lines(
            self._psql(
                """
                SELECT artifact_id || '|' || direction || '|' || depth
                FROM s8.query_lineage_closure('c4://artifact/child', 'ancestors', NULL::integer)
                ORDER BY depth, artifact_id;
                """
            )
        )
        recursive_ancestors = _stdout_lines(
            self._psql(
                """
                SELECT artifact_id || '|' || direction || '|' || depth
                FROM s8.query_lineage_recursive(
                    'c4://artifact/child',
                    'ancestors',
                    NULL::text[],
                    NULL::integer
                )
                ORDER BY depth, artifact_id;
                """
            )
        )
        descendants = _stdout_lines(
            self._psql(
                """
                SELECT artifact_id || '|' || direction || '|' || depth
                FROM s8.query_lineage_closure('c4://artifact/source', 'descendants', NULL::integer)
                ORDER BY depth, artifact_id;
                """
            )
        )
        max_depth_one = _stdout_lines(
            self._psql(
                """
                SELECT artifact_id || '|' || direction || '|' || depth
                FROM s8.query_lineage_closure('c4://artifact/child', 'ancestors', 1)
                ORDER BY depth, artifact_id;
                """
            )
        )
        input_only = _stdout_lines(
            self._psql(
                """
                SELECT artifact_id || '|' || direction || '|' || depth
                FROM s8.query_lineage_recursive(
                    'c4://artifact/model',
                    'ancestors',
                    ARRAY['input']::text[],
                    NULL::integer
                )
                ORDER BY depth, artifact_id;
                """
            )
        )
        default_impact = _stdout_lines(
            self._psql(
                """
                SELECT artifact_id || '|' || depth
                FROM s8.query_impact_set(ARRAY['c4://artifact/source']::text[])
                ORDER BY depth, artifact_id;
                """
            )
        )
        validation_impact = _stdout_lines(
            self._psql(
                """
                SELECT artifact_id || '|' || depth
                FROM s8.query_impact_set(
                    ARRAY['c4://artifact/report']::text[],
                    ARRAY['validation_report']::text[]
                )
                ORDER BY depth, artifact_id;
                """
            )
        )
        closure_verified = self._psql("SELECT s8.verify_lineage_closure('c4://artifact/child');")
        reader_count = self._psql(
            """
            SET ROLE argus_s8_reader;
            SELECT count(*)
            FROM s8.query_lineage_recursive(
                'c4://artifact/child',
                'ancestors',
                NULL::text[],
                NULL::integer
            );
            """
        )

        self.assertEqual(
            closure_ancestors,
            [
                "c4://artifact/child|self|0",
                "c4://artifact/model|ancestor|1",
                "c4://artifact/dataset|ancestor|2",
                "c4://artifact/report|ancestor|2",
                "c4://artifact/source|ancestor|3",
            ],
        )
        self.assertEqual(recursive_ancestors, closure_ancestors)
        self.assertEqual(
            descendants,
            [
                "c4://artifact/source|self|0",
                "c4://artifact/dataset|descendant|1",
                "c4://artifact/model|descendant|2",
                "c4://artifact/child|descendant|3",
            ],
        )
        self.assertEqual(
            max_depth_one,
            [
                "c4://artifact/child|self|0",
                "c4://artifact/model|ancestor|1",
            ],
        )
        self.assertEqual(
            input_only,
            [
                "c4://artifact/model|self|0",
                "c4://artifact/dataset|ancestor|1",
                "c4://artifact/source|ancestor|2",
            ],
        )
        self.assertEqual(
            default_impact,
            [
                "c4://artifact/dataset|1",
                "c4://artifact/model|2",
                "c4://artifact/child|3",
            ],
        )
        self.assertEqual(validation_impact, ["c4://artifact/model|1"])
        self.assertEqual(closure_verified.stdout.strip(), "t")
        self.assertEqual(reader_count.stdout.strip(), "5")

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

    def test_merkle_checkpoint_function_requires_latest_signed_leaf(self) -> None:
        zero_root = "blake3:" + ("0" * 64)
        first_root = "blake3:leaf-root-1"
        second_root = "blake3:leaf-root-2"
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
            SELECT s8.append_ledger_leaf(
                'c4://artifact/b',
                'blake3:record-2',
                2,
                '{first_root}',
                '{second_root}'
            );
            """
        )
        stale_checkpoint = self._psql(
            f"""
            SET ROLE argus_s8_ledger_writer;
            SELECT s8.append_merkle_checkpoint(
                1,
                '{first_root}',
                'hmac-sha256:stale',
                's8-ledger-key'
            );
            """,
            check=False,
        )
        bad_signature = self._psql(
            f"""
            SET ROLE argus_s8_ledger_writer;
            SELECT s8.append_merkle_checkpoint(
                2,
                '{second_root}',
                'placeholder:bad',
                's8-ledger-key'
            );
            """,
            check=False,
        )
        appended = self._psql(
            f"""
            SET ROLE argus_s8_ledger_writer;
            SELECT s8.append_merkle_checkpoint(
                2,
                '{second_root}',
                'hmac-sha256:valid-test-signature',
                's8-ledger-key'
            );
            SELECT s8.append_merkle_checkpoint(
                2,
                '{second_root}',
                'hmac-sha256:valid-test-signature',
                's8-ledger-key'
            );
            """
        )
        direct_checkpoint = self._psql(
            f"""
            SET ROLE argus_s8_ledger_writer;
            INSERT INTO s8.merkle_checkpoint (seq, root, signature, signer_key_id)
            VALUES (2, '{second_root}', 'hmac-sha256:direct', 's8-ledger-key');
            """,
            check=False,
        )
        checkpoint_count = self._psql("SELECT count(*) FROM s8.merkle_checkpoint;")

        self.assertNotEqual(stale_checkpoint.returncode, 0)
        self.assertIn("checkpoint does not match latest ledger leaf", stale_checkpoint.stderr)
        self.assertNotEqual(bad_signature.returncode, 0)
        self.assertIn("unsupported checkpoint signature algorithm", bad_signature.stderr)
        self.assertEqual(appended.returncode, 0)
        self.assertNotEqual(direct_checkpoint.returncode, 0)
        self.assertIn("permission denied", direct_checkpoint.stderr)
        self.assertEqual(checkpoint_count.stdout.strip(), "1")

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

    def test_migration_runner_records_checksum_and_rejects_drift(self) -> None:
        first_count = self._psql("SELECT count(*) FROM s8.schema_migration;")
        reapplied = self._apply_s8_migrations()
        second_count = self._psql("SELECT count(*) FROM s8.schema_migration;")
        self._psql(
            """
            UPDATE s8.schema_migration
            SET checksum_sha256 = 'sha256-drift'
            WHERE migration_id = '001_append_only_schema';
            """
        )
        drift = self._apply_s8_migrations(check=False)

        self.assertEqual(first_count.stdout.strip(), "3")
        self.assertIn("already applied with matching checksum", reapplied.stdout)
        self.assertEqual(second_count.stdout.strip(), "3")
        self.assertNotEqual(drift.returncode, 0)
        self.assertIn("checksum drift", drift.stderr)

    def test_reproducibility_manifest_and_check_functions_are_append_only(self) -> None:
        self._commit_record("c4://artifact/model", sequence=1, kind="model")
        original_hash = self._psql(
            """
            SELECT content_hash
            FROM s8.artifact_record
            WHERE artifact_id = 'c4://artifact/model';
            """
        )
        manifest = self._psql(
            """
            WITH manifest AS (
                SELECT s8.get_reproducibility_manifest('c4://artifact/model') AS payload
            )
            SELECT (payload->>'content_hash') || '|' || (payload->>'kind')
            FROM manifest;
            """
        )
        first = self._psql(
            """
            SET ROLE argus_s8_ledger_writer;
            SELECT s8.record_reproducibility_check(
                's8-check-1',
                'c4://artifact/model',
                'blake3:rerun',
                'PASS',
                'numeric_abs_tolerance'
            );
            """
        )
        second = self._psql(
            """
            SET ROLE argus_s8_ledger_writer;
            SELECT s8.record_reproducibility_check(
                's8-check-1',
                'c4://artifact/model',
                'blake3:rerun',
                'PASS',
                'numeric_abs_tolerance'
            );
            """
        )
        conflict = self._psql(
            """
            SET ROLE argus_s8_ledger_writer;
            SELECT s8.record_reproducibility_check(
                's8-check-1',
                'c4://artifact/model',
                'blake3:changed',
                'FAIL',
                'numeric_abs_tolerance'
            );
            """,
            check=False,
        )
        direct_insert = self._psql(
            """
            SET ROLE argus_s8_ledger_writer;
            INSERT INTO s8.reproducibility_check (
                check_id,
                artifact_id,
                rerun_content_hash,
                verdict,
                tolerance_id
            ) VALUES (
                's8-check-direct',
                'c4://artifact/model',
                'blake3:direct',
                'PASS',
                'hash_equal'
            );
            """,
            check=False,
        )
        reader_manifest = self._psql(
            """
            SET ROLE argus_s8_reader;
            SELECT s8.get_reproducibility_manifest('c4://artifact/model')->>'kind';
            """
        )
        reader_record_denied = self._psql(
            """
            SET ROLE argus_s8_reader;
            SELECT s8.record_reproducibility_check(
                's8-check-reader',
                'c4://artifact/model',
                'blake3:reader',
                'PASS',
                NULL
            );
            """,
            check=False,
        )
        check_count = self._psql("SELECT count(*) FROM s8.reproducibility_check;")
        final_hash = self._psql(
            """
            SELECT content_hash
            FROM s8.artifact_record
            WHERE artifact_id = 'c4://artifact/model';
            """
        )

        self.assertEqual(manifest.stdout.strip(), "blake3:1|model")
        self.assertEqual(first.stdout.strip(), "t")
        self.assertEqual(second.stdout.strip(), "f")
        self.assertNotEqual(conflict.returncode, 0)
        self.assertIn("already exists with different payload", conflict.stderr)
        self.assertNotEqual(direct_insert.returncode, 0)
        self.assertIn("permission denied", direct_insert.stderr)
        self.assertEqual(reader_manifest.stdout.strip(), "model")
        self.assertNotEqual(reader_record_denied.returncode, 0)
        self.assertIn("permission denied", reader_record_denied.stderr)
        self.assertEqual(check_count.stdout.strip(), "1")
        self.assertEqual(final_hash.stdout.strip(), original_hash.stdout.strip())

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

    def _apply_s8_migrations(self, *, check: bool = True) -> subprocess.CompletedProcess[str]:
        command = [
            "python3",
            str(MIGRATION_SCRIPT),
            "--host",
            str(self.pg_host),
            "--database",
            self.pg_database,
            "--migration",
            str(MIGRATIONS_DIR),
        ]
        if self.pg_port is not None:
            command.extend(["--port", str(self.pg_port)])
        return subprocess.run(command, check=check, text=True, capture_output=True)

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


def _stdout_lines(result: subprocess.CompletedProcess[str]) -> list[str]:
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


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
