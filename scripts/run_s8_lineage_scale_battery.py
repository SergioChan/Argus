#!/usr/bin/env python3
"""Run the S8-T12 lineage scale battery against a real PostgreSQL schema."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
import secrets
from tempfile import TemporaryDirectory
from typing import Any

import psycopg


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nodes", type=int, default=100_000)
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument("--slo-seconds", type=float, default=2.0)
    parser.add_argument("--evidence-file", type=Path)
    args = parser.parse_args()

    if args.nodes < 3:
        raise SystemExit("--nodes must be at least 3")
    if args.samples < 1:
        raise SystemExit("--samples must be at least 1")
    if not _has_local_postgres_tools() and not shutil.which("docker"):
        raise SystemExit("PostgreSQL tools or Docker are required for the S8 lineage scale battery")

    with TemporaryDirectory() as tempdir:
        pg = _start_postgres(Path(tempdir))
        try:
            _apply_migrations(pg)
            evidence = _run_battery(pg, nodes=args.nodes, samples=args.samples, slo_seconds=args.slo_seconds)
        finally:
            _stop_postgres(pg)

    output = json.dumps(evidence, indent=2, sort_keys=True)
    print(output)
    if args.evidence_file is not None:
        args.evidence_file.write_text(output + "\n")

    if not evidence["ok"]:
        return 1
    return 0


def _run_battery(pg: dict[str, Any], *, nodes: int, samples: int, slo_seconds: float) -> dict[str, Any]:
    descendant_count = nodes - 2
    dsn = _dsn(pg)
    with psycopg.connect(dsn) as conn:
        with conn.transaction():
            with conn.cursor() as cur:
                _load_graph(cur, descendant_count=descendant_count)
                cur.execute("SET ROLE argus_s8_ledger_writer;")
                cur.execute("SELECT s8.rebuild_lineage_closure();")
                rebuilt_rows = int(cur.fetchone()[0])
                cur.execute("RESET ROLE;")

        correctness = _measure_correctness(conn)
        samples_s = _measure_impact_p95(conn, samples=samples)

    p95 = _percentile(samples_s, 0.95)
    ok = (
        correctness["impact_count"] == descendant_count
        and correctness["recursive_count"] == descendant_count
        and correctness["closure_count"] == descendant_count
        and correctness["impact_hash"] == correctness["recursive_hash"] == correctness["closure_hash"]
        and correctness["drift_count"] == 0
        and rebuilt_rows == (2 * descendant_count) + 1
        and p95 < slo_seconds
    )
    return {
        "ok": ok,
        "battery": "s8-lineage-scale",
        "nodes": nodes,
        "descendant_count": descendant_count,
        "samples": samples,
        "slo_seconds": slo_seconds,
        "p95_seconds": p95,
        "max_seconds": max(samples_s),
        "min_seconds": min(samples_s),
        "rebuilt_closure_rows": rebuilt_rows,
        "correctness": correctness,
    }


def _load_graph(cur: psycopg.Cursor[Any], *, descendant_count: int) -> None:
    cur.execute(
        """
        INSERT INTO s8.artifact_record (
            artifact_id,
            content_hash,
            kind,
            producer,
            lineage,
            record_hash,
            merkle_seq
        )
        VALUES
            (
                'c4://scale/root',
                'blake3:scale-root',
                'external_source',
                '{"subsystem":"S8","version":"scale"}'::jsonb,
                '{"input_refs":[],"code_ref":"git:scale-root","environment_digest":"oci:scale-root"}'::jsonb,
                'blake3:scale-record-root',
                1
            ),
            (
                'c4://scale/seed',
                'blake3:scale-seed',
                'dataset',
                '{"subsystem":"S8","version":"scale"}'::jsonb,
                '{"input_refs":["c4://scale/root"],"code_ref":"git:scale-seed","environment_digest":"oci:scale-seed"}'::jsonb,
                'blake3:scale-record-seed',
                2
            );
        """
    )
    cur.execute(
        """
        INSERT INTO s8.artifact_record (
            artifact_id,
            content_hash,
            kind,
            producer,
            lineage,
            record_hash,
            merkle_seq
        )
        SELECT
            'c4://scale/node-' || lpad(gs::text, 6, '0'),
            'blake3:scale-node-' || gs::text,
            'model',
            '{"subsystem":"S8","version":"scale"}'::jsonb,
            jsonb_build_object(
                'input_refs',
                jsonb_build_array('c4://scale/seed'),
                'code_ref',
                'git:scale-node-' || gs::text,
                'environment_digest',
                'oci:scale-node-' || gs::text
            ),
            'blake3:scale-record-node-' || gs::text,
            gs + 2
        FROM generate_series(1, %s) AS gs;
        """,
        (descendant_count,),
    )
    cur.execute(
        """
        INSERT INTO s8.lineage_edge (src_artifact_id, dst_artifact_id, edge_type, role)
        VALUES ('c4://scale/root', 'c4://scale/seed', 'input', NULL);
        """
    )
    cur.execute(
        """
        INSERT INTO s8.lineage_edge (src_artifact_id, dst_artifact_id, edge_type, role)
        SELECT
            'c4://scale/seed',
            'c4://scale/node-' || lpad(gs::text, 6, '0'),
            'input',
            NULL
        FROM generate_series(1, %s) AS gs;
        """,
        (descendant_count,),
    )


def _measure_correctness(conn: psycopg.Connection[Any]) -> dict[str, Any]:
    with conn.cursor() as cur:
        cur.execute(
            """
            WITH impact AS (
                SELECT artifact_id
                FROM s8.query_impact_set(ARRAY['c4://scale/seed']::text[], ARRAY['input']::text[])
            )
            SELECT count(*), md5(string_agg(artifact_id, ',' ORDER BY artifact_id))
            FROM impact;
            """
        )
        impact_count, impact_hash = cur.fetchone()
        cur.execute(
            """
            WITH recursive AS (
                SELECT artifact_id
                FROM s8.query_lineage_recursive(
                    'c4://scale/seed',
                    'descendants',
                    ARRAY['input']::text[],
                    NULL::integer
                )
                WHERE direction = 'descendant'
            )
            SELECT count(*), md5(string_agg(artifact_id, ',' ORDER BY artifact_id))
            FROM recursive;
            """
        )
        recursive_count, recursive_hash = cur.fetchone()
        cur.execute(
            """
            WITH closure AS (
                SELECT artifact_id
                FROM s8.query_lineage_closure('c4://scale/seed', 'descendants', NULL::integer)
                WHERE direction = 'descendant'
            )
            SELECT count(*), md5(string_agg(artifact_id, ',' ORDER BY artifact_id))
            FROM closure;
            """
        )
        closure_count, closure_hash = cur.fetchone()
        cur.execute("SELECT count(*) FROM s8.lineage_closure_drift('c4://scale/seed');")
        drift_count = int(cur.fetchone()[0])
    return {
        "impact_count": int(impact_count),
        "impact_hash": impact_hash,
        "recursive_count": int(recursive_count),
        "recursive_hash": recursive_hash,
        "closure_count": int(closure_count),
        "closure_hash": closure_hash,
        "drift_count": drift_count,
    }


def _measure_impact_p95(conn: psycopg.Connection[Any], *, samples: int) -> list[float]:
    measurements: list[float] = []
    with conn.cursor() as cur:
        for _ in range(samples):
            started = time.perf_counter()
            cur.execute(
                """
                SELECT count(*)
                FROM s8.query_impact_set(ARRAY['c4://scale/seed']::text[], ARRAY['input']::text[]);
                """
            )
            cur.fetchone()
            measurements.append(time.perf_counter() - started)
    return measurements


def _percentile(values: list[float], fraction: float) -> float:
    if len(values) == 1:
        return values[0]
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(len(ordered) * fraction) - 1))
    return ordered[index]


def _start_postgres(root: Path) -> dict[str, Any]:
    if not _has_local_postgres_tools():
        return _start_docker_postgres()

    data_dir = root / "pgdata"
    socket_dir = root / "socket"
    socket_dir.mkdir()
    port = _free_port()
    try:
        _run_checked(["initdb", "-A", "trust", "--nosync", "-D", str(data_dir)])
    except RuntimeError as exc:
        if "could not create shared memory segment" not in str(exc):
            raise
        if shutil.which("psql"):
            try:
                return _start_existing_postgres_database()
            except RuntimeError:
                if not shutil.which("docker"):
                    raise
        return _start_docker_postgres()
    _run_checked(
        [
            "pg_ctl",
            "-D",
            str(data_dir),
            "-l",
            str(root / "postgres.log"),
            "-o",
            f"-k {socket_dir} -p {port} -c listen_addresses=''",
            "-w",
            "start",
        ]
    )
    return {"data_dir": data_dir, "socket_dir": socket_dir, "port": port, "database": "postgres"}


def _has_local_postgres_tools() -> bool:
    return all(shutil.which(binary) for binary in ("initdb", "pg_ctl"))


def _start_docker_postgres() -> dict[str, Any]:
    if not shutil.which("docker"):
        raise RuntimeError("Docker is required when local PostgreSQL tools are unavailable")
    port = _free_port()
    result = _run_checked(
        [
            "docker",
            "run",
            "--rm",
            "-d",
            "-e",
            "POSTGRES_HOST_AUTH_METHOD=trust",
            "-p",
            f"127.0.0.1:{port}:5432",
            "postgres:16",
        ]
    )
    pg = {
        "docker_container": result.stdout.strip(),
        "host": "127.0.0.1",
        "port": port,
        "database": "postgres",
    }
    deadline = time.monotonic() + 60
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with psycopg.connect(_dsn(pg), connect_timeout=2) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1;")
                    cur.fetchone()
            return pg
        except psycopg.OperationalError as exc:
            last_error = exc
            time.sleep(1)
    _stop_postgres(pg)
    raise RuntimeError(f"Docker PostgreSQL did not become ready: {last_error}")


def _start_existing_postgres_database() -> dict[str, Any]:
    database = f"argus_s8_scale_{os.getpid()}_{secrets.token_hex(4)}"
    roles = _run_checked(
        [
            "psql",
            "-X",
            "-q",
            "-t",
            "-A",
            "-h",
            "127.0.0.1",
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
    preexisting_roles = {line.strip() for line in roles.stdout.splitlines() if line.strip()}
    _run_checked(
        [
            "psql",
            "-X",
            "-q",
            "-h",
            "127.0.0.1",
            "-d",
            "postgres",
            "-c",
            f"CREATE DATABASE {database};",
        ]
    )
    return {
        "external": True,
        "host": "127.0.0.1",
        "port": None,
        "database": database,
        "preexisting_roles": preexisting_roles,
    }


def _stop_postgres(pg: dict[str, Any]) -> None:
    if pg.get("docker_container"):
        subprocess.run(
            ["docker", "rm", "-f", str(pg["docker_container"])],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return
    if pg.get("external"):
        subprocess.run(
            [
                "psql",
                "-X",
                "-q",
                "-h",
                str(pg["host"]),
                "-d",
                "postgres",
                "-c",
                f"DROP DATABASE IF EXISTS {pg['database']};",
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        preexisting_roles = set(pg.get("preexisting_roles", set()))
        for role in ("argus_s8_ledger_writer", "argus_s8_reader"):
            if role not in preexisting_roles:
                subprocess.run(
                    [
                        "psql",
                        "-X",
                        "-q",
                        "-h",
                        str(pg["host"]),
                        "-d",
                        "postgres",
                        "-c",
                        f"DROP ROLE IF EXISTS {role};",
                    ],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
        return
    subprocess.run(
        ["pg_ctl", "-D", str(pg["data_dir"]), "-m", "fast", "-w", "stop"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _apply_migrations(pg: dict[str, Any]) -> None:
    migration_dir = ROOT / "db" / "s8"
    with psycopg.connect(_dsn(pg), autocommit=True) as conn:
        for migration in sorted(migration_dir.glob("*.sql")):
            migration_id = migration.stem
            checksum = hashlib.sha256(migration.read_bytes()).hexdigest()
            with conn.cursor() as cur:
                cur.execute("SELECT to_regclass('s8.schema_migration') IS NOT NULL;")
                table_exists = bool(cur.fetchone()[0])
                existing = None
                if table_exists:
                    cur.execute(
                        "SELECT checksum_sha256 FROM s8.schema_migration WHERE migration_id = %s;",
                        (migration_id,),
                    )
                    row = cur.fetchone()
                    existing = None if row is None else row[0]
                if existing == checksum:
                    continue
                if existing is not None:
                    raise RuntimeError(
                        f"S8 migration checksum drift for {migration_id}: "
                        f"recorded={existing} current={checksum}"
                    )
                cur.execute(migration.read_text())
                cur.execute(
                    """
                    INSERT INTO s8.schema_migration (migration_id, checksum_sha256)
                    VALUES (%s, %s)
                    ON CONFLICT (migration_id) DO NOTHING;
                    """,
                    (migration_id, checksum),
                )


def _dsn(pg: dict[str, Any]) -> str:
    host = pg.get("socket_dir") or pg["host"]
    if pg.get("port") is None:
        return f"host={host} dbname={pg['database']}"
    return f"host={host} port={pg['port']} dbname={pg['database']}"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


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
    try:
        sys.exit(main())
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        sys.exit(1)
