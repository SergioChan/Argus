from __future__ import annotations

import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
from tempfile import TemporaryDirectory
import unittest

from argus_core import (
    CheckResult,
    InMemoryVerifierProfileRegistry,
    S3Verifier,
    VerifierProfileRegistryError,
)
from argus_runtime.s3_profile_registry import PostgresVerifierProfileRegistry
from argusverify import C3ReportSigner


ROOT = Path(__file__).resolve().parents[1]
MIGRATION_SCRIPT = ROOT / "scripts" / "apply_s3_migrations.py"


def _profile_spec(profile_id: str = "ewpt-recap") -> dict[str, object]:
    return {
        "profile_id": profile_id,
        "subtopic": "electroweak.phase_transition",
        "checks": ["INJECTION", "NULL_CONTROL", "PHYSICAL_CONSISTENCY", "CALIBRATION"],
        "thresholds": {
            "INJECTION": {"recovery_rate_min": 0.9},
            "CALIBRATION": {"nominal_coverage": 0.68, "tolerance": 0.05},
        },
        "determinism_policy": {"class": "seeded", "seed": 17},
        "independence_policy": {"requires_cross_code": False},
        "cost_estimate": {"max_wallclock_s": 3.0, "max_cost_usd": 0.02},
        "review_signatures": [
            {
                "reviewer_id": "s3-profile-registrar",
                "signed_at": "2026-07-06T00:00:00Z",
                "signature": "hmac-sha256:" + "a" * 64,
            }
        ],
    }


class S3VerifierProfileRegistryTests(unittest.TestCase):
    def test_revision_is_immutable_after_next_revision_and_report_pins_revision(self) -> None:
        registry = InMemoryVerifierProfileRegistry()
        revision_one = registry.publish(_profile_spec())
        original_bytes = revision_one.spec_json_bytes

        next_spec = _profile_spec()
        next_spec["thresholds"] = {
            "INJECTION": {"recovery_rate_min": 0.95},
            "CALIBRATION": {"nominal_coverage": 0.68, "tolerance": 0.03},
        }
        revision_two = registry.publish(next_spec)

        reread = registry.get(profile_id=revision_one.profile_id, revision=revision_one.revision)
        self.assertEqual(1, revision_one.revision)
        self.assertEqual(2, revision_two.revision)
        self.assertEqual(original_bytes, reread.spec_json_bytes)
        self.assertNotEqual(revision_one.spec_hash, revision_two.spec_hash)

        signer = C3ReportSigner(key_id="s3-k1", secret=b"test-secret")
        report = S3Verifier(verifier_id="s3-referee", signer_key_id="s3-k1", signer=signer).build_report(
            profile_ref=revision_one.profile_ref,
            frozen_pipeline_ref="c4://artifact/frozen-pipeline",
            checks=(CheckResult(check="INJECTION", status="PASS"),),
            proponent_id="builder-1",
        )
        self.assertEqual(revision_one.profile_ref, report["profile_ref"])
        self.assertIn("/r1", report["profile_ref"])

    def test_profile_public_projection_matches_c3_profile_shape(self) -> None:
        revision = InMemoryVerifierProfileRegistry().publish(_profile_spec())

        self.assertEqual(
            {
                "profile_id": "ewpt-recap",
                "revision": 1,
                "subtopic": "electroweak.phase_transition",
                "checks": ["INJECTION", "NULL_CONTROL", "PHYSICAL_CONSISTENCY", "CALIBRATION"],
                "cost_estimate": {"max_cost_usd": 0.02, "max_wallclock_s": 3.0},
            },
            revision.to_c3_profile(),
        )

    def test_publish_requires_review_signature_and_json_safe_spec(self) -> None:
        registry = InMemoryVerifierProfileRegistry()
        missing_signature = _profile_spec()
        missing_signature["review_signatures"] = []

        with self.assertRaises(VerifierProfileRegistryError) as missing:
            registry.publish(missing_signature)
        self.assertEqual("S3_PROFILE_REVIEW_SIGNATURE_REQUIRED", missing.exception.code)

        non_json = _profile_spec()
        non_json["thresholds"] = {"bad": object()}
        with self.assertRaises(VerifierProfileRegistryError) as invalid:
            registry.publish(non_json)
        self.assertEqual("S3_PROFILE_JSON_INVALID", invalid.exception.code)

    def test_status_changes_are_append_only_and_do_not_mutate_spec_json(self) -> None:
        registry = InMemoryVerifierProfileRegistry()
        revision = registry.publish(_profile_spec())
        original_bytes = revision.spec_json_bytes

        deprecated = registry.deprecate(profile_id=revision.profile_id, revision=revision.revision, reason="superseded")
        revoked = registry.revoke(profile_id=revision.profile_id, revision=revision.revision, reason="bad threshold")
        reread = registry.get(profile_id=revision.profile_id, revision=revision.revision)

        self.assertEqual("deprecated", deprecated.status)
        self.assertEqual("revoked", revoked.status)
        self.assertEqual("revoked", reread.status)
        self.assertEqual(original_bytes, reread.spec_json_bytes)
        self.assertEqual(("active", "deprecated", "revoked"), tuple(event.status for event in registry.status_events()))


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@unittest.skipUnless(
    shutil.which("initdb") and shutil.which("pg_ctl") and shutil.which("psql"),
    "PostgreSQL command-line tools are required for S3 profile registry tests",
)
class S3PostgresProfileRegistryTests(unittest.TestCase):
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
        cls.pg_database = f"argus_s3_py_test_{os.getpid()}_{secrets.token_hex(4)}"
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
                    "WHERE rolname IN ('argus_s3_reader', 'argus_s3_profile_writer') "
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
            for role in ("argus_s3_profile_writer", "argus_s3_reader"):
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
        self._psql("DROP SCHEMA IF EXISTS s3 CASCADE;")
        self._apply_s3_migrations()

    def test_postgres_registry_preserves_revision_bytes_after_new_publish(self) -> None:
        registry = PostgresVerifierProfileRegistry(dsn=self._postgres_dsn(), db_role="argus_s3_profile_writer")
        revision_one = registry.publish(_profile_spec())
        original_bytes = revision_one.spec_json_bytes

        next_spec = _profile_spec()
        next_spec["thresholds"] = {"INJECTION": {"recovery_rate_min": 0.99}}
        revision_two = registry.publish(next_spec)
        reread = registry.get_by_ref(revision_one.profile_ref)

        self.assertEqual(1, revision_one.revision)
        self.assertEqual(2, revision_two.revision)
        self.assertEqual(original_bytes, reread.spec_json_bytes)
        self.assertEqual("active", reread.status)

    def test_postgres_registry_is_append_only_for_revisions_and_status_events(self) -> None:
        registry = PostgresVerifierProfileRegistry(dsn=self._postgres_dsn(), db_role="argus_s3_profile_writer")
        revision = registry.publish(_profile_spec())
        registry.deprecate(profile_id=revision.profile_id, revision=revision.revision, reason="superseded")

        update = self._psql(
            "UPDATE s3.verifier_profile_revision SET subtopic = 'mutated';",
            check=False,
        )
        delete = self._psql(
            "DELETE FROM s3.verifier_profile_status_event;",
            check=False,
        )
        truncate = self._psql(
            "TRUNCATE s3.verifier_profile_revision CASCADE;",
            check=False,
        )

        self.assertNotEqual(0, update.returncode)
        self.assertNotEqual(0, delete.returncode)
        self.assertNotEqual(0, truncate.returncode)
        self.assertIn("append-only table verifier_profile_revision", update.stderr)
        self.assertIn("append-only table verifier_profile_status_event", delete.stderr)
        self.assertIn("append-only table verifier_profile_revision", truncate.stderr)
        self.assertEqual(2, len(registry.status_events(profile_id=revision.profile_id, revision=revision.revision)))

    def _postgres_dsn(self) -> str:
        parts = [f"host={self.pg_host}", f"dbname={self.pg_database}"]
        if self.pg_port is not None:
            parts.append(f"port={self.pg_port}")
        return " ".join(parts)

    def _apply_s3_migrations(self) -> None:
        command = [
            "python3",
            str(MIGRATION_SCRIPT),
            "--host",
            self.pg_host,
            "--database",
            self.pg_database,
        ]
        if self.pg_port is not None:
            command.extend(["--port", str(self.pg_port)])
        _run_checked(command)

    def _psql(self, sql: str, *, check: bool = True) -> subprocess.CompletedProcess[str]:
        command = [
            "psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-X",
            "-q",
            "-h",
            self.pg_host,
            "-d",
            self.pg_database,
            "-c",
            sql,
        ]
        if self.pg_port is not None:
            command[8:8] = ["-p", str(self.pg_port)]
        result = subprocess.run(command, check=False, text=True, capture_output=True)
        if check and result.returncode != 0:
            raise RuntimeError(
                "command failed: "
                + " ".join(command)
                + "\nstdout:\n"
                + result.stdout
                + "\nstderr:\n"
                + result.stderr
            )
        return result


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
