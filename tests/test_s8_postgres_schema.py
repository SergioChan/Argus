from __future__ import annotations

from pathlib import Path
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
    def setUp(self) -> None:
        self.tempdir = TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.data_dir = self.root / "pgdata"
        self.socket_dir = self.root / "socket"
        self.socket_dir.mkdir()
        self.port = _free_port()
        subprocess.run(
            ["initdb", "-A", "trust", "--nosync", "-D", str(self.data_dir)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "pg_ctl",
                "-D",
                str(self.data_dir),
                "-o",
                f"-k {self.socket_dir} -p {self.port} -c listen_addresses=''",
                "-w",
                "start",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self._psql_file(SCHEMA_SQL)

    def tearDown(self) -> None:
        subprocess.run(
            ["pg_ctl", "-D", str(self.data_dir), "-m", "fast", "-w", "stop"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.tempdir.cleanup()

    def test_ledger_writer_can_insert_records_and_append_lineage_edge(self) -> None:
        self._psql(
            """
            SET ROLE argus_s8_ledger_writer;
            INSERT INTO s8.artifact_record (
                artifact_id, content_hash, kind, producer, lineage, record_hash, merkle_seq
            ) VALUES
                ('c4://artifact/a', 'blake3:a', 'dataset', '{"subsystem":"S6","version":"1"}',
                 '{"input_refs":[],"code_ref":"git:a","environment_digest":"oci:a"}', 'blake3:record-a', 1),
                ('c4://artifact/b', 'blake3:b', 'model', '{"subsystem":"S2","version":"1"}',
                 '{"input_refs":["c4://artifact/a"],"code_ref":"git:b","environment_digest":"oci:b"}',
                 'blake3:record-b', 2);
            SELECT s8.insert_lineage_edge('c4://artifact/a', 'c4://artifact/b', 'input', 'training_data');
            RESET ROLE;
            """
        )

        result = self._psql(
            """
            SELECT count(*)
            FROM s8.lineage_closure
            WHERE ancestor_id = 'c4://artifact/a'
              AND descendant_id = 'c4://artifact/b'
              AND depth = 1;
            """
        )

        self.assertEqual(result.stdout.strip(), "1")

    def test_lineage_function_maintains_transitive_closure_and_rejects_cycles(self) -> None:
        self._insert_record("c4://artifact/a", sequence=1)
        self._insert_record("c4://artifact/b", sequence=2)
        self._insert_record("c4://artifact/c", sequence=3)
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

    def test_writer_role_cannot_bypass_lineage_function(self) -> None:
        self._insert_record("c4://artifact/a", sequence=1)
        self._insert_record("c4://artifact/b", sequence=2)
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

        self.assertNotEqual(direct_edge.returncode, 0)
        self.assertIn("permission denied", direct_edge.stderr)
        self.assertNotEqual(direct_closure.returncode, 0)
        self.assertIn("permission denied", direct_closure.stderr)

    def test_update_and_delete_are_rejected_even_for_owner(self) -> None:
        self._insert_record("c4://artifact/a", sequence=1)

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

        self.assertNotEqual(denied.returncode, 0)
        self.assertIn("permission denied", denied.stderr)

    def _insert_record(self, artifact_ref: str, *, sequence: int) -> None:
        self._psql(
            f"""
            SET ROLE argus_s8_ledger_writer;
            INSERT INTO s8.artifact_record (
                artifact_id, content_hash, kind, producer, lineage, record_hash, merkle_seq
            ) VALUES (
                '{artifact_ref}', 'blake3:{sequence}', 'dataset', '{{"subsystem":"S6","version":"1"}}',
                '{{"input_refs":[],"code_ref":"git:a","environment_digest":"oci:a"}}',
                'blake3:record-{sequence}', {sequence}
            );
            RESET ROLE;
            """
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
        return [
            "psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-X",
            "-q",
            "-t",
            "-A",
            "-h",
            str(self.socket_dir),
            "-p",
            str(self.port),
            "-d",
            "postgres",
        ]


if __name__ == "__main__":
    unittest.main()
