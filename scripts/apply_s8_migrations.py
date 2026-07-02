#!/usr/bin/env python3
"""Apply S8 PostgreSQL migrations with checksum drift detection."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MIGRATION = ROOT / "db" / "s8" / "001_append_only_schema.sql"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=os.environ.get("PGHOST", "127.0.0.1"))
    parser.add_argument("--port", default=os.environ.get("PGPORT"))
    parser.add_argument("--database", default=os.environ.get("PGDATABASE", "postgres"))
    parser.add_argument("--user", default=os.environ.get("PGUSER"))
    parser.add_argument("--migration", type=Path, default=DEFAULT_MIGRATION)
    args = parser.parse_args()

    migration = args.migration.resolve()
    migration_id = migration.stem
    checksum = _sha256(migration)
    existing = _existing_checksum(args, migration_id)
    if existing == checksum:
        print(f"S8 migration {migration_id} already applied with matching checksum")
        return 0
    if existing is not None:
        print(
            f"S8 migration checksum drift for {migration_id}: recorded={existing} current={checksum}",
            file=sys.stderr,
        )
        return 2

    _psql(args, ["-f", str(migration)])
    _psql(
        args,
        [
            "-c",
            (
                "INSERT INTO s8.schema_migration (migration_id, checksum_sha256) "
                f"VALUES ({_sql_literal(migration_id)}, {_sql_literal(checksum)}) "
                "ON CONFLICT (migration_id) DO NOTHING;"
            ),
        ],
    )
    print(f"S8 migration {migration_id} applied with checksum {checksum}")
    return 0


def _existing_checksum(args: argparse.Namespace, migration_id: str) -> str | None:
    exists = _psql(
        args,
        [
            "-c",
            "SELECT to_regclass('s8.schema_migration') IS NOT NULL;",
        ],
        check=False,
    )
    if exists.returncode != 0 or exists.stdout.strip() != "t":
        return None

    result = _psql(
        args,
        [
            "-c",
            "SELECT checksum_sha256 FROM s8.schema_migration "
            f"WHERE migration_id = {_sql_literal(migration_id)};",
        ],
    )
    value = result.stdout.strip()
    return value or None


def _psql(args: argparse.Namespace, extra: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    command = [
        "psql",
        "-v",
        "ON_ERROR_STOP=1",
        "-X",
        "-q",
        "-t",
        "-A",
        "-h",
        args.host,
    ]
    if args.port:
        command.extend(["-p", str(args.port)])
    if args.user:
        command.extend(["-U", args.user])
    command.extend(["-d", args.database])
    command.extend(extra)
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


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        sys.exit(1)
