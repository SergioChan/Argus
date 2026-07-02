from __future__ import annotations

from dataclasses import asdict
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
from tempfile import TemporaryDirectory
import unittest

from argus_core import (
    ArtifactRecord,
    DatasetRegistry,
    DatasetSplit,
    HashMismatchError,
    IllegalTierError,
    InMemoryArtifactStore,
    InMemoryObjectStore,
    Lineage,
    Producer,
    SignatureInvalidError,
    hash_bytes,
    hash_json,
)
from argus_runtime.s8_persistence import PostgresArtifactStore, report_verifier_from_env
from argusverify import C3ReportSigner, C3ReportVerifier, InMemoryVerifierTrustStore


ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS_DIR = ROOT / "db" / "s8"
MIGRATION_SCRIPT = ROOT / "scripts" / "apply_s8_migrations.py"


class _TestPostgresLedgerWriter:
    ledger_writer_kind = "test-postgres"
    checkpoint_signer_kind = "test-only"

    def __init__(self, test_case: "S8PostgresSchemaTests") -> None:
        self._test_case = test_case

    def commit_record(self, record: ArtifactRecord) -> dict[str, object]:
        import psycopg
        from psycopg import sql
        from psycopg.types.json import Jsonb

        record_hash = hash_json(asdict(record))
        with psycopg.connect(self._test_case._postgres_dsn()) as conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute(sql.SQL("SET ROLE {};").format(sql.Identifier("argus_s8_ledger_writer")))
                    cur.execute(
                        """
                        SELECT sequence, root
                        FROM s8.ledger_leaf
                        ORDER BY sequence DESC
                        LIMIT 1;
                        """
                    )
                    latest = cur.fetchone()
                    if latest is None:
                        sequence = 1
                        previous_root = "blake3:" + "0" * 64
                    else:
                        sequence = int(latest[0]) + 1
                        previous_root = str(latest[1])
                    root = hash_bytes(f"{previous_root}|{record_hash}|{sequence}".encode("utf-8"))
                    cur.execute(
                        """
                        SELECT s8.commit_artifact_record(
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                        );
                        """,
                        (
                            record.artifact_ref,
                            record.content_hash,
                            record.kind,
                            Jsonb(asdict(record.producer)),
                            Jsonb(asdict(record.lineage)),
                            record_hash,
                            sequence,
                            record.claim_tier,
                            record.validation_report_ref,
                            list(record.lineage.input_refs),
                            record.created_at,
                            record.size_bytes,
                        ),
                    )
                    inserted = bool(cur.fetchone()[0])
                    if inserted:
                        cur.execute(
                            """
                            SELECT s8.append_ledger_leaf(%s, %s, %s, %s, %s);
                            """,
                            (record.artifact_ref, record_hash, sequence, previous_root, root),
                        )
        return {"status": "ok", "checkpoint": None}


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

    def _postgres_store(
        self,
        *,
        object_store: InMemoryObjectStore | None = None,
        report_verifier: C3ReportVerifier | None = None,
    ) -> PostgresArtifactStore:
        return PostgresArtifactStore(
            dsn=self._postgres_dsn(),
            object_store=object_store or InMemoryObjectStore(),
            db_role="argus_s8_ledger_writer",
            ledger_writer=_TestPostgresLedgerWriter(self),
            report_verifier=report_verifier,
        )

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
        direct_truncate = self._psql(
            """
            SET ROLE argus_s8_ledger_writer;
            TRUNCATE s8.ledger_leaf;
            """,
            check=False,
        )

        self.assertNotEqual(direct_record.returncode, 0)
        self.assertIn("permission denied", direct_record.stderr)
        self.assertNotEqual(direct_edge.returncode, 0)
        self.assertIn("permission denied", direct_edge.stderr)
        self.assertNotEqual(direct_closure.returncode, 0)
        self.assertIn("permission denied", direct_closure.stderr)
        self.assertNotEqual(direct_truncate.returncode, 0)
        self.assertIn("permission denied", direct_truncate.stderr)

    def test_update_delete_and_truncate_are_rejected_even_for_owner(self) -> None:
        self._commit_record("c4://artifact/a", sequence=1)

        update = self._psql(
            "UPDATE s8.artifact_record SET kind = 'tampered' WHERE artifact_id = 'c4://artifact/a';",
            check=False,
        )
        delete = self._psql("DELETE FROM s8.artifact_record WHERE artifact_id = 'c4://artifact/a';", check=False)
        truncate = self._psql("TRUNCATE s8.ledger_leaf;", check=False)

        self.assertNotEqual(update.returncode, 0)
        self.assertIn("append-only table artifact_record", update.stderr)
        self.assertNotEqual(delete.returncode, 0)
        self.assertIn("append-only table artifact_record", delete.stderr)
        self.assertNotEqual(truncate.returncode, 0)
        self.assertIn("append-only table ledger_leaf", truncate.stderr)

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

        self.assertEqual(first_count.stdout.strip(), "11")
        self.assertIn("already applied with matching checksum", reapplied.stdout)
        self.assertEqual(second_count.stdout.strip(), "11")
        self.assertNotEqual(drift.returncode, 0)
        self.assertIn("checksum drift", drift.stderr)

    def test_postgres_store_record_hash_matches_refreshed_created_at(self) -> None:
        store = self._postgres_store()

        record = store.create_artifact(
            kind="model",
            payload={"weights": [1, 2, 3]},
            producer=Producer(subsystem="S2", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:r8-m4", environment_digest="oci:r8-m4"),
        )

        refreshed = store.get_artifact_record(record.artifact_ref)
        stored_hash = self._psql(
            f"""
            SELECT record_hash
            FROM s8.artifact_record
            WHERE artifact_id = {_sql_literal(record.artifact_ref)};
            """
        ).stdout.strip()

        self.assertEqual(refreshed.created_at, record.created_at)
        self.assertEqual(hash_json(asdict(refreshed)), stored_hash)

    def test_postgres_store_targeted_reads_ignore_unrelated_tampered_object(self) -> None:
        object_store = InMemoryObjectStore()
        store = self._postgres_store(object_store=object_store)
        good = store.create_artifact(
            artifact_ref="c4://r8-m6/good",
            kind="model",
            payload={"weights": [1]},
            producer=Producer(subsystem="S2", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:r8-m6-good", environment_digest="oci:r8-m6-good"),
        )
        tampered = store.create_artifact(
            artifact_ref="c4://r8-m6/tampered",
            kind="model",
            payload={"weights": [2]},
            producer=Producer(subsystem="S2", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:r8-m6-tampered", environment_digest="oci:r8-m6-tampered"),
        )
        object_store._objects[tampered.content_hash] = b'{"tampered":true}'

        self.assertEqual(store.record_count, 2)
        self.assertEqual(store.get_artifact_record(good.artifact_ref).artifact_ref, good.artifact_ref)
        self.assertEqual(store.get_artifact_record(tampered.artifact_ref).size_bytes, len(b'{"weights":[2]}'))
        self.assertEqual(store.get_artifact(good.artifact_ref), b'{"weights":[1]}')
        with self.assertRaises(HashMismatchError):
            store.get_artifact(tampered.artifact_ref)
        with self.assertRaises(HashMismatchError):
            store.get_record(tampered.artifact_ref)

    def test_postgres_store_delegates_commit_to_configured_ledger_writer(self) -> None:
        class RecordingLedgerWriter:
            def __init__(self) -> None:
                self.records: list[ArtifactRecord] = []

            def commit_record(self, record: ArtifactRecord) -> dict[str, object]:
                self.records.append(record)
                return {"status": "ok", "checkpoint": None}

        ledger_writer = RecordingLedgerWriter()
        store = PostgresArtifactStore(
            dsn=self._postgres_dsn(),
            object_store=InMemoryObjectStore(),
            db_role="argus_s8_ledger_writer",
            ledger_writer=ledger_writer,
        )
        record = ArtifactRecord(
            artifact_ref="c4://r8-s8t07/delegated",
            kind="model",
            content_hash=hash_bytes(b"{}"),
            size_bytes=2,
            producer=Producer(subsystem="S2", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:r8-s8t07", environment_digest="oci:r8-s8t07"),
            created_at="2026-07-02T00:00:00Z",
        )

        store._commit_record(record)
        record_count = self._psql(
            "SELECT count(*) FROM s8.artifact_record WHERE artifact_id = 'c4://r8-s8t07/delegated';"
        )

        self.assertEqual(store.ledger_writer_kind, "rust-subprocess")
        self.assertEqual(ledger_writer.records, [record])
        self.assertEqual(record_count.stdout.strip(), "0")

    def test_postgres_store_requires_ledger_writer(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "S8 Rust ledger writer is required"):
            PostgresArtifactStore(
                dsn=self._postgres_dsn(),
                object_store=InMemoryObjectStore(),
                db_role="argus_s8_ledger_writer",
            )

    def test_postgres_store_reproducibility_manifest_and_checks_use_pg_append_only(self) -> None:
        store = self._postgres_store()
        payload = {
            "metric": 1.0,
            "nondeterminism_tolerance": {
                "comparator_id": "numeric_abs_tolerance",
                "params": {"field": "metric", "abs_tolerance": 0.1},
            },
        }
        record = store.create_artifact(
            kind="model",
            payload=payload,
            producer=Producer(subsystem="S2", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:repro", environment_digest="oci:repro", seeds=("seed-1",)),
        )

        manifest = store.get_reproducibility_manifest(record.artifact_ref)
        first = store.record_reproducibility_check(
            record.artifact_ref,
            rerun_payload={**payload, "metric": 1.05},
            tolerance_id="metric-abs-0.1",
        )
        second = store.record_reproducibility_check(
            record.artifact_ref,
            rerun_payload={**payload, "metric": 1.05},
            tolerance_id="metric-abs-0.1",
        )
        third = store.record_reproducibility_check(
            record.artifact_ref,
            rerun_payload={**payload, "metric": 1.08},
            tolerance_id="metric-abs-0.1",
        )
        persisted = self._psql(
            f"""
            SELECT count(*) || '|' || count(DISTINCT check_id) || '|' || max(verdict) || '|' || max(tolerance_id)
            FROM s8.reproducibility_check
            WHERE artifact_id = {_sql_literal(record.artifact_ref)};
            """
        )

        self.assertEqual(manifest.artifact_ref, record.artifact_ref)
        self.assertEqual(manifest.lineage.seeds, ("seed-1",))
        self.assertEqual(manifest.nondeterminism_tolerance["comparator_id"], "numeric_abs_tolerance")
        self.assertEqual(first.verdict, "PASS")
        self.assertEqual(first.comparator_id, "numeric_abs_tolerance")
        self.assertEqual(first.check_id, second.check_id)
        self.assertNotEqual(first.check_id, third.check_id)
        self.assertEqual(persisted.stdout.strip(), "2|2|PASS|metric-abs-0.1")

    def test_postgres_store_exports_and_verifies_audit_slice(self) -> None:
        store = self._postgres_store()
        dataset = store.create_artifact(
            kind="dataset",
            payload={"rows": [1]},
            producer=Producer(subsystem="S2", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:data", environment_digest="oci:data"),
        )
        model = store.create_artifact(
            kind="model",
            payload={"weights": [1]},
            producer=Producer(subsystem="S2", version="0.0.0"),
            lineage=Lineage(input_refs=(dataset.artifact_ref,), code_ref="git:model", environment_digest="oci:model"),
        )
        self._psql(
            """
            SET ROLE argus_s8_ledger_writer;
            WITH latest AS (
                SELECT sequence, root
                FROM s8.ledger_leaf
                ORDER BY sequence DESC
                LIMIT 1
            )
            SELECT s8.append_merkle_checkpoint(
                latest.sequence,
                latest.root,
                'hmac-sha256:test-audit-signature',
                's8-ledger-key'
            )
            FROM latest;
            RESET ROLE;
            """
        )

        audit_slice = store.export_audit_slice((model.artifact_ref,))
        slice_verification = store.verify_audit_slice(audit_slice)
        chain_verification = store.verify_audit_chain()

        self.assertEqual(audit_slice["leaves"][0]["artifact_id"], model.artifact_ref)
        self.assertEqual(audit_slice["merkle_checkpoints"][0]["sequence"], 2)
        self.assertEqual(audit_slice["inclusion_proofs"][0]["artifact_id"], model.artifact_ref)
        self.assertTrue(slice_verification["valid"])
        self.assertTrue(chain_verification["valid"])

        tampered_root = "blake3:" + ("f" * 64)
        self._psql(
            f"""
            ALTER TABLE s8.ledger_leaf DISABLE TRIGGER ledger_leaf_append_only;
            ALTER TABLE s8.merkle_checkpoint DISABLE TRIGGER merkle_checkpoint_append_only;
            UPDATE s8.ledger_leaf
            SET root = '{tampered_root}'
            WHERE sequence = 2;
            UPDATE s8.merkle_checkpoint
            SET root = '{tampered_root}'
            WHERE seq = 2;
            ALTER TABLE s8.ledger_leaf ENABLE TRIGGER ledger_leaf_append_only;
            ALTER TABLE s8.merkle_checkpoint ENABLE TRIGGER merkle_checkpoint_append_only;
            """
        )
        tampered_slice = store.export_audit_slice((model.artifact_ref,))
        tampered_slice_verification = store.verify_audit_slice(tampered_slice)
        tampered_chain_verification = store.verify_audit_chain()

        self.assertFalse(tampered_slice_verification["valid"])
        self.assertEqual(tampered_slice_verification["break_sequence"], 2)
        self.assertEqual(tampered_slice_verification["reason"], "root_mismatch")
        self.assertFalse(tampered_chain_verification["valid"])
        self.assertEqual(tampered_chain_verification["break_sequence"], 2)
        self.assertEqual(tampered_chain_verification["reason"], "root_mismatch")

    def test_postgres_store_uses_report_verifier_for_tier_coupling(self) -> None:
        trust_store = InMemoryVerifierTrustStore()
        trust_store.register_key("s3-key", b"s3-secret")
        signer = C3ReportSigner(key_id="s3-key", secret=b"s3-secret")
        object_store = InMemoryObjectStore()
        store = self._postgres_store(object_store=object_store, report_verifier=C3ReportVerifier(trust_store))
        report = store.create_artifact(
            kind="report",
            payload=signer.sign(self._validation_report(claim_tier="recapitulated-known")),
            producer=Producer(subsystem="S3", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:verify", environment_digest="oci:verify"),
        )
        model = store.create_artifact(
            kind="model",
            payload={"weights": [1, 2, 3], "uncertainty_tag": {"kind": "interval", "radius": 0.1}},
            producer=Producer(subsystem="S2", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:model", environment_digest="oci:model"),
            claim_tier="recapitulated-known",
            validation_report_ref=report.artifact_ref,
        )
        count_after_valid = store.record_count

        tampered = signer.sign(self._validation_report(claim_tier="recapitulated-known"))
        tampered["aggregate"]["score"] = 0.1
        with self.assertRaises(SignatureInvalidError) as invalid:
            store.create_artifact(
                kind="report",
                payload=tampered,
                producer=Producer(subsystem="S3", version="0.0.0"),
                lineage=Lineage(input_refs=(), code_ref="git:verify-tamper", environment_digest="oci:verify"),
            )
        with self.assertRaises(IllegalTierError) as mismatch:
            store.create_artifact(
                kind="model",
                payload={"weights": [4], "uncertainty_tag": {"kind": "interval", "radius": 0.1}},
                producer=Producer(subsystem="S2", version="0.0.0"),
                lineage=Lineage(input_refs=(), code_ref="git:model-mismatch", environment_digest="oci:model"),
                claim_tier="novel-needs-human",
                validation_report_ref=report.artifact_ref,
            )

        refreshed = self._postgres_store(object_store=object_store, report_verifier=C3ReportVerifier(trust_store))
        self.assertEqual(store.report_verifier_kind, "argusverify")
        self.assertEqual(model.validation_report_ref, report.artifact_ref)
        self.assertEqual(refreshed.get_artifact_record(model.artifact_ref).claim_tier, "recapitulated-known")
        self.assertEqual(invalid.exception.reason, "signature_invalid")
        self.assertEqual(mismatch.exception.reason, "tier must match validation report claim_tier")
        self.assertEqual(store.record_count, count_after_valid)

    def test_report_verifier_env_requires_and_parses_keys(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "ARGUS_S8_C3_VERIFIER_KEYS_JSON"):
            report_verifier_from_env({"ARGUS_S8_REQUIRE_REPORT_VERIFIER": "1"})

        verifier = report_verifier_from_env(
            {
                "ARGUS_S8_REQUIRE_REPORT_VERIFIER": "1",
                "ARGUS_S8_C3_VERIFIER_KEYS_JSON": json.dumps({"s3-key": "s3-secret"}),
            }
        )
        self.assertIsNotNone(verifier)
        signed = C3ReportSigner(key_id="s3-key", secret=b"s3-secret").sign(
            self._validation_report(claim_tier="recapitulated-known")
        )
        self.assertTrue(verifier.verify(signed).valid)

    def test_read_query_functions_resolve_refs_filter_page_and_grant_reader(self) -> None:
        self._commit_record(
            "c4://artifact/dataset-a",
            sequence=1,
            kind="dataset",
            producer={"subsystem": "S6", "version": "1", "actor_id": "ingest-agent"},
            lineage_extra={"job_id": "job-42", "contamination_index_version": "contam-v1"},
        )
        self._commit_record(
            "c4://artifact/report-a",
            sequence=2,
            kind="validation_report",
            producer={"subsystem": "S3", "version": "1", "actor_id": "verifier-agent"},
            lineage_extra={"job_id": "job-42"},
        )
        self._commit_record(
            "c4://artifact/model-a",
            sequence=3,
            kind="model",
            input_refs=["c4://artifact/dataset-a"],
            validation_report_ref="c4://artifact/report-a",
            claim_tier="recapitulated-known",
            producer={"subsystem": "S2", "version": "1", "actor_id": "builder-a"},
            lineage_extra={"job_id": "job-42", "contamination_index_version": "contam-v1"},
        )
        self._commit_record(
            "c4://artifact/model-b",
            sequence=4,
            kind="model",
            claim_tier="ran-toy",
            producer={"subsystem": "S2", "version": "2", "actor_id": "builder-b"},
            lineage_extra={"job_id": "job-99", "contamination_index_version": "contam-v2"},
        )

        by_artifact_id = self._psql("SELECT s8.get_artifact_record('c4://artifact/model-a')->>'content_hash';")
        by_content_hash = self._psql("SELECT s8.get_artifact_record('blake3:3')->>'artifact_id';")
        missing = self._psql("SELECT s8.get_artifact_record('c4://artifact/missing');", check=False)
        models = self._psql(
            f"""
            SELECT string_agg(record->>'artifact_id', ',' ORDER BY record->>'artifact_id')
            FROM s8.query_artifacts({_jsonb_literal({"kind": "model"})}, 10, 0) AS query(record);
            """
        )
        actor = self._psql(
            f"""
            SELECT record->>'artifact_id'
            FROM s8.query_artifacts({_jsonb_literal({"actor_id": "builder-a"})}, 10, 0) AS query(record);
            """
        )
        job_contam = self._psql(
            f"""
            SELECT string_agg(record->>'artifact_id', ',' ORDER BY record->>'merkle_seq')
            FROM s8.query_artifacts(
                {_jsonb_literal({"job_id": "job-42", "contamination_index_version": "contam-v1"})},
                10,
                0
            ) AS query(record);
            """
        )
        second_model_page = self._psql(
            f"""
            SELECT record->>'artifact_id'
            FROM s8.query_artifacts({_jsonb_literal({"kind": "model"})}, 1, 1) AS query(record);
            """
        )
        old_range_count = self._psql(
            f"""
            SELECT count(*)
            FROM s8.query_artifacts({_jsonb_literal({"created_after": "2000-01-01T00:00:00Z"})}, 100, 0);
            """
        )
        reader_count = self._psql(
            f"""
            SET ROLE argus_s8_reader;
            SELECT count(*)
            FROM s8.query_artifacts({_jsonb_literal({"producer_subsystem": "S2"})}, 10, 0);
            """
        )
        bad_limit = self._psql(
            f"SELECT count(*) FROM s8.query_artifacts({_jsonb_literal({'kind': 'model'})}, 0, 0);",
            check=False,
        )

        self.assertEqual(by_artifact_id.stdout.strip(), "blake3:3")
        self.assertEqual(by_content_hash.stdout.strip(), "c4://artifact/model-a")
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("not found", missing.stderr)
        self.assertEqual(models.stdout.strip(), "c4://artifact/model-a,c4://artifact/model-b")
        self.assertEqual(actor.stdout.strip(), "c4://artifact/model-a")
        self.assertEqual(job_contam.stdout.strip(), "c4://artifact/dataset-a,c4://artifact/model-a")
        self.assertEqual(second_model_page.stdout.strip(), "c4://artifact/model-b")
        self.assertEqual(old_range_count.stdout.strip(), "4")
        self.assertEqual(reader_count.stdout.strip(), "2")
        self.assertNotEqual(bad_limit.returncode, 0)
        self.assertIn("limit must be between 1 and 1000", bad_limit.stderr)

    def test_query_artifacts_matches_python_store_for_shared_filters(self) -> None:
        python_store = InMemoryArtifactStore()
        python_records = [
            python_store.create_artifact(
                artifact_ref="c4://parity/dataset-a",
                kind="dataset",
                payload={"rows": [1]},
                producer=Producer(subsystem="S6", version="1", actor_id="ingest-agent"),
                lineage=Lineage(
                    input_refs=(),
                    code_ref="git:1",
                    environment_digest="oci:1",
                    job_id="job-42",
                    contamination_index_version="contam-v1",
                ),
                created_at="2026-07-02T00:00:00.125Z",
            ),
            python_store.create_artifact(
                artifact_ref="c4://parity/report-a",
                kind="validation_report",
                payload={"report": "unsigned"},
                producer=Producer(subsystem="S3", version="1"),
                lineage=Lineage(
                    input_refs=(),
                    code_ref="git:2",
                    environment_digest="oci:2",
                    actor_id="verifier-lineage",
                    job_id="job-42",
                ),
                created_at="2026-07-01T17:05:00-07:00",
            ),
            python_store.create_artifact(
                artifact_ref="c4://parity/model-a",
                kind="model",
                payload={"weights": [1]},
                producer=Producer(subsystem="S2", version="1", actor_id="builder-a"),
                lineage=Lineage(
                    input_refs=("c4://parity/dataset-a",),
                    code_ref="git:3",
                    environment_digest="oci:3",
                    job_id="job-42",
                    contamination_index_version="contam-v1",
                ),
                validation_report_ref="c4://parity/report-a",
                created_at="2026-07-02T01:00:00.500+00:00",
            ),
            python_store.create_artifact(
                artifact_ref="c4://parity/model-b",
                kind="model",
                payload={"weights": [2]},
                producer=Producer(subsystem="S2", version="2", actor_id="builder-b"),
                lineage=Lineage(
                    input_refs=(),
                    code_ref="git:4",
                    environment_digest="oci:4",
                    job_id="job-99",
                    contamination_index_version="contam-v2",
                ),
                created_at="2026-07-01T19:00:00-07:00",
            ),
        ]
        for sequence, record in enumerate(python_records, start=1):
            self._commit_record(
                record.artifact_ref,
                sequence=sequence,
                kind=record.kind,
                input_refs=list(record.lineage.input_refs),
                validation_report_ref=record.validation_report_ref,
                claim_tier=record.claim_tier,
                producer={
                    "subsystem": record.producer.subsystem,
                    "version": record.producer.version,
                    "actor_id": record.producer.actor_id,
                    "job_id": record.producer.job_id,
                },
                lineage_extra={
                    "actor_id": record.lineage.actor_id,
                    "job_id": record.lineage.job_id,
                    "contamination_index_version": record.lineage.contamination_index_version,
                },
                content_hash=record.content_hash,
                created_at=record.created_at,
            )

        query_filters = (
            {"kind": "model"},
            {"content_hash": python_records[0].content_hash},
            {"producer_subsystem": "S2"},
            {"producer_version": "1"},
            {"actor_id": "builder-a"},
            {"actor_id": "verifier-lineage"},
            {"job_id": "job-42"},
            {"contamination_index_version": "contam-v1"},
            {"validation_report_ref": "c4://parity/report-a"},
            {"created_after": "2000-01-01T00:00:00Z"},
            {"created_after": "3000-01-01T00:00:00Z"},
            {"created_before": "3000-01-01T00:00:00Z"},
            {"created_before": "2000-01-01T00:00:00Z"},
            {"created_after": "2026-07-01T17:30:00-07:00"},
            {"created_after": "2026-07-02T00:05:00.250+00:00"},
            {"created_before": "2026-07-01T17:30:00-07:00"},
            {"created_before": "2026-07-02T00:05:00.250+00:00"},
        )

        for query_filter in query_filters:
            with self.subTest(query_filter=query_filter):
                self.assertEqual(
                    _python_query_refs(python_store, query_filter),
                    self._postgres_query_refs(query_filter),
                )

    def test_dataset_registry_functions_are_versioned_typed_and_append_only(self) -> None:
        splits_v1 = [
            {
                "split_id": "train",
                "role": "train",
                "content_hash": "blake3:train",
                "row_count": 10,
                "schema_ref": "c4://schema/ewpt/v1",
                "access_scope": "agent-readable",
            },
            {
                "split_id": "blind",
                "role": "blind",
                "content_hash": "blake3:blind",
                "row_count": 3,
                "schema_ref": "c4://schema/ewpt/v1",
                "access_scope": "verifier-only",
                "label_seal_ref": "c4://labels/blind",
            },
        ]
        splits_v2 = [
            {
                "split_id": "train",
                "role": "train",
                "content_hash": "blake3:train-v2",
                "row_count": 12,
                "schema_ref": "c4://schema/ewpt/v2",
                "access_scope": "agent-readable",
            }
        ]
        invalid_blind_splits = [
            {
                "split_id": "blind",
                "role": "blind",
                "content_hash": "blake3:blind",
                "row_count": 3,
                "schema_ref": "c4://schema/ewpt/v1",
                "access_scope": "agent-readable",
            }
        ]
        self._commit_record("c4://dataset/ewpt/1.0.0", sequence=1, kind="dataset")
        self._commit_record("c4://dataset/ewpt/1.1.0", sequence=2, kind="dataset")
        self._commit_record("c4://artifact/model", sequence=3, kind="model")

        first = self._psql(
            f"""
            SET ROLE argus_s8_ledger_writer;
            SELECT s8.register_dataset(
                'ewpt-corpus',
                '1.0.0',
                'c4://dataset/ewpt/1.0.0',
                {_jsonb_literal(splits_v1)},
                'contam-2026-07-01'
            );
            """
        )
        second = self._psql(
            f"""
            SET ROLE argus_s8_ledger_writer;
            SELECT s8.register_dataset(
                'ewpt-corpus',
                '1.0.0',
                'c4://dataset/ewpt/1.0.0',
                {_jsonb_literal(splits_v1)},
                'contam-2026-07-01'
            );
            """
        )
        third = self._psql(
            f"""
            SET ROLE argus_s8_ledger_writer;
            SELECT s8.register_dataset(
                'ewpt-corpus',
                '1.1.0',
                'c4://dataset/ewpt/1.1.0',
                {_jsonb_literal(splits_v2)},
                'contam-2026-07-02'
            );
            """
        )
        conflict = self._psql(
            f"""
            SET ROLE argus_s8_ledger_writer;
            SELECT s8.register_dataset(
                'ewpt-corpus',
                '1.0.0',
                'c4://dataset/ewpt/1.0.0',
                {_jsonb_literal(splits_v2)},
                'contam-2026-07-01'
            );
            """,
            check=False,
        )
        invalid_blind = self._psql(
            f"""
            SET ROLE argus_s8_ledger_writer;
            SELECT s8.register_dataset(
                'ewpt-invalid',
                '1.0.0',
                'c4://dataset/ewpt/1.0.0',
                {_jsonb_literal(invalid_blind_splits)},
                'contam-2026-07-01'
            );
            """,
            check=False,
        )
        wrong_kind = self._psql(
            f"""
            SET ROLE argus_s8_ledger_writer;
            SELECT s8.register_dataset(
                'ewpt-wrong-kind',
                '1.0.0',
                'c4://artifact/model',
                {_jsonb_literal(splits_v1)},
                'contam-2026-07-01'
            );
            """,
            check=False,
        )
        reader_v1_artifact = self._psql(
            """
            SET ROLE argus_s8_reader;
            SELECT s8.get_dataset('ewpt-corpus', '1.0.0')->'provenance_ref'->>'artifact_id';
            """
        )
        reader_latest = self._psql(
            """
            SET ROLE argus_s8_reader;
            SELECT s8.get_dataset('ewpt-corpus', NULL)->>'version';
            """
        )
        reader_versions = self._psql(
            """
            SET ROLE argus_s8_reader;
            SELECT string_agg(version, ',' ORDER BY version)
            FROM s8.list_dataset_versions('ewpt-corpus');
            """
        )
        reader_masked_splits = self._psql(
            """
            SET ROLE argus_s8_reader;
            SELECT string_agg(
                (value->>'split_id')
                || ':' || COALESCE(value->>'content_hash', '<null>')
                || ':' || COALESCE(value->>'label_seal_ref', '<null>'),
                ',' ORDER BY value->>'split_id'
            )
            FROM jsonb_array_elements(s8.get_dataset('ewpt-corpus', '1.0.0')->'splits') AS item(value);
            """
        )
        direct_insert = self._psql(
            f"""
            SET ROLE argus_s8_ledger_writer;
            INSERT INTO s8.dataset_registry (
                dataset_id,
                version,
                dataset_artifact_id,
                splits,
                contamination_index_version
            ) VALUES (
                'direct',
                '1.0.0',
                'c4://dataset/ewpt/1.0.0',
                {_jsonb_literal(splits_v1)},
                'contam'
            );
            """,
            check=False,
        )
        reader_direct_select = self._psql(
            """
            SET ROLE argus_s8_reader;
            SELECT count(*) FROM s8.dataset_registry;
            """,
            check=False,
        )
        writer_direct_select = self._psql(
            """
            SET ROLE argus_s8_ledger_writer;
            SELECT count(*) FROM s8.dataset_registry;
            """,
            check=False,
        )
        update = self._psql(
            """
            UPDATE s8.dataset_registry
            SET contamination_index_version = 'tampered'
            WHERE dataset_id = 'ewpt-corpus';
            """,
            check=False,
        )
        row_count = self._psql("SELECT count(*) FROM s8.dataset_registry;")

        self.assertEqual(first.stdout.strip(), "t")
        self.assertEqual(second.stdout.strip(), "f")
        self.assertEqual(third.stdout.strip(), "t")
        self.assertNotEqual(conflict.returncode, 0)
        self.assertIn("already exists with different payload", conflict.stderr)
        self.assertNotEqual(invalid_blind.returncode, 0)
        self.assertIn("verifier-only access_scope", invalid_blind.stderr)
        self.assertNotEqual(wrong_kind.returncode, 0)
        self.assertIn("has kind model", wrong_kind.stderr)
        self.assertEqual(reader_v1_artifact.stdout.strip(), "c4://dataset/ewpt/1.0.0")
        self.assertEqual(reader_latest.stdout.strip(), "1.1.0")
        self.assertEqual(reader_versions.stdout.strip(), "1.0.0,1.1.0")
        self.assertEqual(reader_masked_splits.stdout.strip(), "blind:<null>:<null>,train:blake3:train:<null>")
        self.assertNotEqual(direct_insert.returncode, 0)
        self.assertIn("permission denied", direct_insert.stderr)
        self.assertNotEqual(reader_direct_select.returncode, 0)
        self.assertIn("permission denied", reader_direct_select.stderr)
        self.assertNotEqual(writer_direct_select.returncode, 0)
        self.assertIn("permission denied", writer_direct_select.stderr)
        self.assertNotEqual(update.returncode, 0)
        self.assertIn("append-only table dataset_registry", update.stderr)
        self.assertEqual(row_count.stdout.strip(), "2")

    def test_dataset_latest_uses_numeric_semver_ordering(self) -> None:
        splits = [
            {
                "split_id": "train",
                "role": "train",
                "content_hash": "blake3:train",
                "row_count": 10,
                "schema_ref": "c4://schema/ewpt/v1",
                "access_scope": "agent-readable",
            }
        ]
        self._commit_record("c4://dataset/ewpt/1.10.0", sequence=1, kind="dataset")
        self._commit_record("c4://dataset/ewpt/1.9.0", sequence=2, kind="dataset")

        self._psql(
            f"""
            SET ROLE argus_s8_ledger_writer;
            SELECT s8.register_dataset(
                'semver-corpus',
                '1.10.0',
                'c4://dataset/ewpt/1.10.0',
                {_jsonb_literal(splits)},
                'contam-2026-07-10'
            );
            SELECT s8.register_dataset(
                'semver-corpus',
                '1.9.0',
                'c4://dataset/ewpt/1.9.0',
                {_jsonb_literal(splits)},
                'contam-2026-07-09'
            );
            """
        )
        latest = self._psql(
            """
            SET ROLE argus_s8_reader;
            SELECT s8.get_dataset('semver-corpus', NULL)->>'version';
            """
        )
        versions = self._psql(
            """
            SET ROLE argus_s8_reader;
            SELECT string_agg(version, ',')
            FROM s8.list_dataset_versions('semver-corpus');
            """
        )
        latest_resolved = self._psql(
            """
            SET ROLE argus_s8_reader;
            SELECT s8.resolve_split('semver-corpus', NULL, 'train', 'agent')->>'version';
            """
        )

        self.assertEqual(latest.stdout.strip(), "1.10.0")
        self.assertEqual(versions.stdout.strip(), "1.9.0,1.10.0")
        self.assertEqual(latest_resolved.stdout.strip(), "1.10.0")

    def test_dataset_registry_matches_python_for_semver_and_masked_splits(self) -> None:
        python_registry = DatasetRegistry(artifact_store=InMemoryArtifactStore())
        out_of_order_splits = (
            DatasetSplit(
                split_id="train",
                role="train",
                content_hash="blake3:train",
                row_count=10,
                schema_ref="c4://schema/ewpt/v1",
                access_scope="agent-readable",
            ),
            DatasetSplit(
                split_id="blind",
                role="blind",
                content_hash="blake3:blind",
                row_count=3,
                schema_ref="c4://schema/ewpt/v1",
                access_scope="verifier-only",
                label_seal_ref="c4://labels/blind",
            ),
        )
        older = python_registry.register(
            dataset_id="parity-corpus",
            version="1.10.0",
            splits=out_of_order_splits,
            contamination_index_version="contam-2026-07-10",
        )
        newer_by_write_time_but_older_by_semver = python_registry.register(
            dataset_id="parity-corpus",
            version="1.9.0",
            splits=(out_of_order_splits[0],),
            contamination_index_version="contam-2026-07-09",
        )
        self._commit_record(older.provenance_ref.artifact_ref, sequence=1, kind="dataset")
        self._commit_record(newer_by_write_time_but_older_by_semver.provenance_ref.artifact_ref, sequence=2, kind="dataset")
        self._psql(
            f"""
            SET ROLE argus_s8_ledger_writer;
            SELECT s8.register_dataset(
                'parity-corpus',
                '1.10.0',
                {_sql_literal(older.provenance_ref.artifact_ref)},
                {_jsonb_literal([_split_json(split) for split in out_of_order_splits])},
                'contam-2026-07-10'
            );
            SELECT s8.register_dataset(
                'parity-corpus',
                '1.9.0',
                {_sql_literal(newer_by_write_time_but_older_by_semver.provenance_ref.artifact_ref)},
                {_jsonb_literal([_split_json(out_of_order_splits[0])])},
                'contam-2026-07-09'
            );
            """
        )

        postgres_versions = self._psql(
            """
            SET ROLE argus_s8_reader;
            SELECT string_agg(version, ',')
            FROM s8.list_dataset_versions('parity-corpus');
            """
        )
        postgres_latest = self._psql(
            """
            SET ROLE argus_s8_reader;
            SELECT s8.get_dataset('parity-corpus', NULL)->>'version';
            """
        )
        postgres_split_summary = self._psql(
            """
            SET ROLE argus_s8_reader;
            SELECT string_agg(
                (value->>'split_id')
                || ':' || COALESCE(value->>'content_hash', '<null>')
                || ':' || COALESCE(value->>'label_seal_ref', '<null>'),
                ',' ORDER BY value->>'split_id'
            )
            FROM jsonb_array_elements(s8.get_dataset('parity-corpus', NULL)->'splits') AS item(value);
            """
        )

        self.assertEqual(postgres_versions.stdout.strip(), ",".join(python_registry.list_versions("parity-corpus")))
        self.assertEqual(postgres_latest.stdout.strip(), python_registry.get("parity-corpus").version)
        self.assertEqual(
            postgres_split_summary.stdout.strip(),
            ",".join(_dataset_split_summary(python_registry.get("parity-corpus"))),
        )

    def test_resolve_split_denies_non_verifier_labels_and_audits_verifier_resolution(self) -> None:
        splits = [
            {
                "split_id": "train",
                "role": "train",
                "content_hash": "blake3:train",
                "row_count": 10,
                "schema_ref": "c4://schema/ewpt/v1",
                "access_scope": "agent-readable",
            },
            {
                "split_id": "blind",
                "role": "blind",
                "content_hash": "blake3:blind-features",
                "row_count": 3,
                "schema_ref": "c4://schema/ewpt/v1",
                "access_scope": "verifier-only",
                "label_seal_ref": "c4://labels/blind-sealed",
            },
        ]
        missing_label_splits = [
            {
                "split_id": "blind",
                "role": "blind",
                "content_hash": "blake3:blind-features",
                "row_count": 3,
                "schema_ref": "c4://schema/ewpt/v1",
                "access_scope": "verifier-only",
            },
        ]
        self._commit_record("c4://dataset/ewpt/1.0.0", sequence=1, kind="dataset")

        self._psql(
            f"""
            SET ROLE argus_s8_ledger_writer;
            SELECT s8.register_dataset(
                'ewpt-corpus',
                '1.0.0',
                'c4://dataset/ewpt/1.0.0',
                {_jsonb_literal(splits)},
                'contam-2026-07-01'
            );
            """
        )
        missing_label = self._psql(
            f"""
            SET ROLE argus_s8_ledger_writer;
            SELECT s8.register_dataset(
                'ewpt-missing-label',
                '1.0.0',
                'c4://dataset/ewpt/1.0.0',
                {_jsonb_literal(missing_label_splits)},
                'contam-2026-07-01'
            );
            """,
            check=False,
        )
        agent_train = self._psql(
            """
            SET ROLE argus_s8_reader;
            WITH resolved AS (
                SELECT s8.resolve_split('ewpt-corpus', '1.0.0', 'train', 'agent') AS payload
            )
            SELECT (payload->>'feature_blob_ref') || '|' || COALESCE(payload->>'label_blob_ref', '<null>')
            FROM resolved;
            """
        )
        agent_blind = self._psql(
            """
            SET ROLE argus_s8_reader;
            SELECT s8.resolve_split('ewpt-corpus', '1.0.0', 'blind', 'agent');
            """,
            check=False,
        )
        verifier_blind = self._psql(
            """
            SET ROLE argus_s8_reader;
            WITH resolved AS (
                SELECT s8.resolve_split('ewpt-corpus', '1.0.0', 'blind', 'verifier') AS payload
            )
            SELECT (payload->>'feature_blob_ref') || '|' || (payload->>'label_blob_ref')
            FROM resolved;
            """
        )
        audit = self._psql(
            """
            SELECT count(*) || '|' || string_agg(split_id || ':' || COALESCE(label_seal_ref, '<null>'), ',' ORDER BY resolve_id)
            FROM s8.dataset_resolve_audit;
            """
        )
        direct_insert = self._psql(
            """
            SET ROLE argus_s8_ledger_writer;
            INSERT INTO s8.dataset_resolve_audit (
                dataset_id,
                version,
                split_id,
                requester_scope,
                verdict
            ) VALUES (
                'ewpt-corpus',
                '1.0.0',
                'blind',
                'agent',
                'ALLOWED'
            );
            """,
            check=False,
        )
        update = self._psql(
            """
            UPDATE s8.dataset_resolve_audit
            SET verdict = 'DENIED'
            WHERE dataset_id = 'ewpt-corpus';
            """,
            check=False,
        )

        self.assertNotEqual(missing_label.returncode, 0)
        self.assertIn("requires label_seal_ref", missing_label.stderr)
        self.assertEqual(agent_train.stdout.strip(), "blake3:train|<null>")
        self.assertNotEqual(agent_blind.returncode, 0)
        self.assertIn("SCOPE_DENIED", agent_blind.stderr)
        self.assertNotIn("c4://labels/blind-sealed", agent_blind.stderr)
        self.assertEqual(verifier_blind.stdout.strip(), "blake3:blind-features|c4://labels/blind-sealed")
        self.assertEqual(audit.stdout.strip(), "2|train:<null>,blind:c4://labels/blind-sealed")
        self.assertNotEqual(direct_insert.returncode, 0)
        self.assertIn("permission denied", direct_insert.stderr)
        self.assertNotEqual(update.returncode, 0)
        self.assertIn("append-only table dataset_resolve_audit", update.stderr)

    def test_audit_export_proofs_are_exported_and_weak_sql_verifiers_are_removed(self) -> None:
        zero_root = "blake3:" + ("0" * 64)
        first_root = "blake3:audit-root-1"
        second_root = "blake3:audit-root-2"
        third_root = "blake3:audit-root-3"
        self._commit_record("c4://artifact/source", sequence=1, kind="external_source")
        self._commit_record(
            "c4://artifact/dataset",
            sequence=2,
            kind="dataset",
            input_refs=["c4://artifact/source"],
        )
        self._commit_record(
            "c4://artifact/model",
            sequence=3,
            kind="model",
            input_refs=["c4://artifact/dataset"],
        )
        self._psql(
            f"""
            SET ROLE argus_s8_ledger_writer;
            SELECT s8.append_ledger_leaf(
                'c4://artifact/source',
                'blake3:record-1',
                1,
                '{zero_root}',
                '{first_root}'
            );
            SELECT s8.append_ledger_leaf(
                'c4://artifact/dataset',
                'blake3:record-2',
                2,
                '{first_root}',
                '{second_root}'
            );
            SELECT s8.append_ledger_leaf(
                'c4://artifact/model',
                'blake3:record-3',
                3,
                '{second_root}',
                '{third_root}'
            );
            SELECT s8.append_merkle_checkpoint(
                3,
                '{third_root}',
                'hmac-sha256:audit-signature',
                's8-ledger-key'
            );
            RESET ROLE;
            """
        )

        export_result = self._psql(
            """
            SELECT s8.export_audit_slice(ARRAY['c4://artifact/dataset']::text[]);
            """
        )
        audit_slice = json.loads(export_result.stdout)
        proof = audit_slice["inclusion_proofs"][0]
        removed_verifiers = self._psql(
            """
            SELECT (to_regprocedure('s8.verify_audit_chain()') IS NULL)::text
                || '|'
                || (to_regprocedure('s8.verify_audit_slice(jsonb)') IS NULL)::text;
            """
        )
        direct_chain_call = self._psql("SELECT s8.verify_audit_chain();", check=False)
        reader_slice_call = self._psql(
            """
            SET ROLE argus_s8_reader;
            WITH audit_slice AS (
                SELECT s8.export_audit_slice(ARRAY['c4://artifact/dataset']::text[]) AS payload
            )
            SELECT s8.verify_audit_slice(payload)
            FROM audit_slice;
            """,
            check=False,
        )
        missing_ref = self._psql(
            """
            SELECT s8.export_audit_slice(ARRAY['c4://artifact/missing']::text[]);
            """,
            check=False,
        )

        self.assertEqual(audit_slice["records"][0]["artifact_id"], "c4://artifact/dataset")
        self.assertEqual(audit_slice["leaves"][0]["sequence"], 2)
        self.assertEqual(audit_slice["merkle_checkpoints"][0]["sequence"], 3)
        self.assertEqual(proof["sequence"], 2)
        self.assertEqual(proof["anchor_previous_root"], first_root)
        self.assertEqual([step["sequence"] for step in proof["steps"]], [3])
        self.assertEqual(removed_verifiers.stdout.strip(), "true|true")
        self.assertNotEqual(direct_chain_call.returncode, 0)
        self.assertIn("function s8.verify_audit_chain() does not exist", direct_chain_call.stderr)
        self.assertNotEqual(reader_slice_call.returncode, 0)
        self.assertIn("function s8.verify_audit_slice(jsonb) does not exist", reader_slice_call.stderr)
        self.assertNotEqual(missing_ref.returncode, 0)
        self.assertIn("audit export missing ledger leaves", missing_ref.stderr)

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

    @staticmethod
    def _validation_report(*, claim_tier: str, aggregate_passed: bool = True) -> dict[str, object]:
        return {
            "report_id": "33333333-3333-4333-8333-333333333333",
            "profile_ref": "c4://profile/ewpt-toy/v1",
            "frozen_pipeline_ref": "c4://pipeline/ewpt-toy/baseline",
            "checks": [
                {"check": "INJECTION", "status": "PASS"},
                {"check": "LEAKAGE", "status": "PASS"},
                {"check": "CROSS_CODE", "status": "PASS"},
            ],
            "aggregate": {
                "passed": aggregate_passed,
                "score": 0.98 if aggregate_passed else 0.0,
            },
            "claim_tier": claim_tier,
            "claim_tier_is_candidate": claim_tier == "novel-needs-human",
            "signature": {
                "algorithm": "placeholder",
                "key_id": "placeholder",
                "value": "placeholder",
            },
            "perturbation_pairs": [
                {"perturbation_id": "must-react-1", "kind": "must_react", "verdict": "pass"},
                {"perturbation_id": "must-not-react-1", "kind": "must_not_react", "verdict": "pass"},
            ],
            "insensitivity_flags": [],
            "challenger_panel": {"challenger_ids": ["challenger-a", "challenger-b"], "min_required": 2},
            "independence_attestation_debate": {
                "min_independent_challengers": 2,
                "lineage_disjoint": True,
                "correlation_warning": False,
            },
            "referee": {
                "referee_id": "s3-referee",
                "non_gameable": True,
                "signed_by": "s3-key",
                "distinct_from_proponent": True,
            },
            "debate_ref": "c4://debate/ewpt-toy/example",
        }

    def _commit_record(
        self,
        artifact_ref: str,
        *,
        sequence: int,
        kind: str = "dataset",
        input_refs: list[str] | None = None,
        validation_report_ref: str | None = None,
        claim_tier: str = "ran-toy",
        producer: dict[str, object] | None = None,
        lineage_extra: dict[str, object] | None = None,
        content_hash: str | None = None,
        created_at: str | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        input_refs = input_refs or []
        producer = producer or {"subsystem": "S6", "version": "1"}
        lineage = {
            "input_refs": input_refs,
            "code_ref": f"git:{sequence}",
            "environment_digest": f"oci:{sequence}",
        }
        if lineage_extra:
            lineage.update(lineage_extra)
        validation_ref_sql = "NULL"
        if validation_report_ref is not None:
            validation_ref_sql = _sql_literal(validation_report_ref)
        created_at_sql = "NULL" if created_at is None else f"{_sql_literal(created_at)}::timestamptz"
        return self._psql(
            f"""
            SET ROLE argus_s8_ledger_writer;
            SELECT s8.commit_artifact_record(
                {_sql_literal(artifact_ref)},
                {_sql_literal(content_hash or f"blake3:{sequence}")},
                {_sql_literal(kind)},
                {_jsonb_literal(producer)},
                {_jsonb_literal(lineage)},
                {_sql_literal(f"blake3:record-{sequence}")},
                {sequence},
                {_sql_literal(claim_tier)},
                {validation_ref_sql},
                {_text_array_literal(input_refs)},
                {created_at_sql}
            );
            """,
            check=check,
        )

    def _postgres_query_refs(self, query_filter: dict[str, object]) -> tuple[str, ...]:
        result = self._psql(
            f"""
            SELECT COALESCE(string_agg(record->>'artifact_id', ',' ORDER BY record->>'artifact_id'), '')
            FROM s8.query_artifacts({_jsonb_literal(query_filter)}, 100, 0) AS query(record);
            """
        )
        output = result.stdout.strip()
        if not output:
            return ()
        return tuple(output.split(","))

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

    def _postgres_dsn(self) -> str:
        from psycopg.conninfo import make_conninfo

        kwargs = {"host": str(self.pg_host), "dbname": self.pg_database}
        if self.pg_port is not None:
            kwargs["port"] = str(self.pg_port)
        return make_conninfo("", **kwargs)


def _sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _jsonb_literal(value: object) -> str:
    payload = json.dumps(value, separators=(",", ":"), sort_keys=True)
    return f"{_sql_literal(payload)}::jsonb"


def _text_array_literal(values: list[str]) -> str:
    if not values:
        return "ARRAY[]::text[]"
    return "ARRAY[" + ", ".join(_sql_literal(value) for value in values) + "]::text[]"


def _python_query_refs(store: InMemoryArtifactStore, query_filter: dict[str, object]) -> tuple[str, ...]:
    return tuple(sorted(record.artifact_ref for record in store.query_artifacts(query_filter)))


def _split_json(split: DatasetSplit) -> dict[str, object]:
    payload: dict[str, object] = {
        "split_id": split.split_id,
        "role": split.role,
        "content_hash": split.content_hash,
        "row_count": split.row_count,
        "schema_ref": split.schema_ref,
        "access_scope": split.access_scope,
    }
    if split.label_seal_ref is not None:
        payload["label_seal_ref"] = split.label_seal_ref
    return payload


def _dataset_split_summary(record) -> tuple[str, ...]:
    return tuple(
        sorted(
            f"{split.split_id}:{split.content_hash or '<null>'}:{split.label_seal_ref or '<null>'}"
            for split in record.splits
        )
    )


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
