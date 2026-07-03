#!/usr/bin/env python3
"""Run the S8-T21 read/query scale battery against a real PostgreSQL schema."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import psycopg

import run_s8_lineage_scale_battery as pg_support


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--records", type=int, default=100_000)
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument("--page-size", type=int, default=1000)
    parser.add_argument("--slo-seconds", type=float, default=1.0)
    parser.add_argument("--evidence-file", type=Path)
    args = parser.parse_args()

    if args.records < 1000:
        raise SystemExit("--records must be at least 1000")
    if args.samples < 1:
        raise SystemExit("--samples must be at least 1")
    if args.page_size < 1 or args.page_size > 1000:
        raise SystemExit("--page-size must be between 1 and 1000")

    with TemporaryDirectory() as tempdir:
        pg = pg_support._start_postgres(Path(tempdir))
        try:
            pg_support._apply_migrations(pg)
            evidence = _run_battery(
                pg,
                records=args.records,
                samples=args.samples,
                page_size=args.page_size,
                slo_seconds=args.slo_seconds,
            )
        finally:
            pg_support._stop_postgres(pg)

    output = json.dumps(evidence, indent=2, sort_keys=True)
    print(output)
    if args.evidence_file is not None:
        args.evidence_file.write_text(output + "\n")

    return 0 if evidence["ok"] else 1


def _run_battery(
    pg: dict[str, Any],
    *,
    records: int,
    samples: int,
    page_size: int,
    slo_seconds: float,
) -> dict[str, Any]:
    dsn = pg_support._dsn(pg)
    with psycopg.connect(dsn) as conn:
        with conn.transaction():
            with conn.cursor() as cur:
                _load_records(cur, records=records)
        correctness = _measure_correctness(conn, records=records, page_size=page_size)
        samples_s = _measure_read_query_p95(conn, records=records, samples=samples, page_size=page_size)

    artifact_ref_p95 = pg_support._percentile(samples_s["artifact_ref_lookup"], 0.95)
    content_hash_p95 = pg_support._percentile(samples_s["content_hash_lookup"], 0.95)
    first_page_p95 = pg_support._percentile(samples_s["first_page_query"], 0.95)
    middle_page_p95 = pg_support._percentile(samples_s["middle_page_query"], 0.95)
    max_p95 = max(artifact_ref_p95, content_hash_p95, first_page_p95, middle_page_p95)
    ok = (
        correctness["record_count"] == records
        and correctness["artifact_ref_lookup"] == f"c4://read-scale/model-{records:06d}"
        and correctness["content_hash_lookup"] == f"c4://read-scale/model-{records:06d}"
        and correctness["first_page_count"] == page_size
        and correctness["middle_page_count"] == page_size
        and correctness["query_hash"] == correctness["expected_query_hash"]
        and max_p95 < slo_seconds
    )
    return {
        "ok": ok,
        "battery": "s8-read-query-scale",
        "records": records,
        "samples": samples,
        "page_size": page_size,
        "slo_seconds": slo_seconds,
        "p95_seconds": {
            "artifact_ref_lookup": artifact_ref_p95,
            "content_hash_lookup": content_hash_p95,
            "first_page_query": first_page_p95,
            "middle_page_query": middle_page_p95,
            "max": max_p95,
        },
        "max_seconds": {name: max(values) for name, values in samples_s.items()},
        "min_seconds": {name: min(values) for name, values in samples_s.items()},
        "correctness": correctness,
    }


def _load_records(cur: psycopg.Cursor[Any], *, records: int) -> None:
    cur.execute(
        """
        INSERT INTO s8.artifact_record (
            artifact_id,
            content_hash,
            kind,
            producer,
            lineage,
            claim_tier,
            validation_report_ref,
            record_hash,
            merkle_seq,
            created_at
        )
        SELECT
            'c4://read-scale/model-' || lpad(gs::text, 6, '0'),
            'blake3:read-scale-content-' || gs::text,
            CASE WHEN gs %% 2 = 0 THEN 'model' ELSE 'dataset' END,
            jsonb_build_object(
                'subsystem',
                CASE WHEN gs %% 2 = 0 THEN 'S2' ELSE 'S6' END,
                'version',
                'scale',
                'actor_id',
                'actor-' || (gs %% 32)::text
            ),
            jsonb_build_object(
                'input_refs',
                '[]'::jsonb,
                'code_ref',
                'git:read-scale-' || gs::text,
                'environment_digest',
                'oci:read-scale-' || gs::text,
                'job_id',
                'job-' || (gs %% 64)::text,
                'contamination_index_version',
                'contam-' || (gs %% 8)::text
            ),
            CASE WHEN gs %% 5 = 0 THEN 'recapitulated-known' ELSE 'ran-toy' END,
            NULL,
            'blake3:read-scale-record-' || gs::text,
            gs,
            '2026-07-03T00:00:00Z'::timestamptz + (gs || ' seconds')::interval
        FROM generate_series(1, %s) AS gs;
        """,
        (records,),
    )


def _measure_correctness(
    conn: psycopg.Connection[Any],
    *,
    records: int,
    page_size: int,
) -> dict[str, Any]:
    target_ref = f"c4://read-scale/model-{records:06d}"
    target_hash = f"blake3:read-scale-content-{records}"
    middle_offset = _middle_offset(records, page_size)
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM s8.artifact_record;")
        record_count = int(cur.fetchone()[0])
        cur.execute("SELECT s8.get_artifact_record(%s)->>'artifact_id';", (target_ref,))
        artifact_ref_lookup = cur.fetchone()[0]
        cur.execute("SELECT s8.get_artifact_record(%s)->>'artifact_id';", (target_hash,))
        content_hash_lookup = cur.fetchone()[0]
        cur.execute(
            """
            SELECT count(*), md5(string_agg(record->>'artifact_id', ',' ORDER BY record->>'artifact_id'))
            FROM s8.query_artifacts(
                '{"kind":"model","producer_subsystem":"S2"}'::jsonb,
                %s,
                0
            ) AS query(record);
            """,
            (page_size,),
        )
        first_page_count, query_hash = cur.fetchone()
        cur.execute(
            """
            SELECT count(*)
            FROM s8.query_artifacts(
                '{"kind":"model","producer_subsystem":"S2"}'::jsonb,
                %s,
                %s
            ) AS query(record);
            """,
            (page_size, middle_offset),
        )
        middle_page_count = int(cur.fetchone()[0])
    expected_refs = [f"c4://read-scale/model-{index:06d}" for index in range(2, (2 * page_size) + 1, 2)]
    return {
        "record_count": record_count,
        "artifact_ref_lookup": artifact_ref_lookup,
        "content_hash_lookup": content_hash_lookup,
        "first_page_count": int(first_page_count),
        "middle_page_count": middle_page_count,
        "middle_offset": middle_offset,
        "query_hash": query_hash,
        "expected_query_hash": _md5_join(expected_refs),
    }


def _measure_read_query_p95(
    conn: psycopg.Connection[Any],
    *,
    records: int,
    samples: int,
    page_size: int,
) -> dict[str, list[float]]:
    target_ref = f"c4://read-scale/model-{records:06d}"
    target_hash = f"blake3:read-scale-content-{records}"
    middle_offset = _middle_offset(records, page_size)
    measurements = {
        "artifact_ref_lookup": [],
        "content_hash_lookup": [],
        "first_page_query": [],
        "middle_page_query": [],
    }
    with conn.cursor() as cur:
        for _ in range(samples):
            started = time.perf_counter()
            cur.execute("SELECT s8.get_artifact_record(%s);", (target_ref,))
            cur.fetchone()
            measurements["artifact_ref_lookup"].append(time.perf_counter() - started)

            started = time.perf_counter()
            cur.execute("SELECT s8.get_artifact_record(%s);", (target_hash,))
            cur.fetchone()
            measurements["content_hash_lookup"].append(time.perf_counter() - started)

            started = time.perf_counter()
            cur.execute(
                """
                SELECT count(*)
                FROM s8.query_artifacts(
                    '{"kind":"model","producer_subsystem":"S2"}'::jsonb,
                    %s,
                    0
                ) AS query(record);
                """,
                (page_size,),
            )
            cur.fetchone()
            measurements["first_page_query"].append(time.perf_counter() - started)

            started = time.perf_counter()
            cur.execute(
                """
                SELECT count(*)
                FROM s8.query_artifacts(
                    '{"kind":"model","producer_subsystem":"S2"}'::jsonb,
                    %s,
                    %s
                ) AS query(record);
                """,
                (page_size, middle_offset),
            )
            cur.fetchone()
            measurements["middle_page_query"].append(time.perf_counter() - started)
    return measurements


def _middle_offset(records: int, page_size: int) -> int:
    matching_records = records // 2
    return max(0, min(matching_records - page_size, matching_records // 2))


def _md5_join(values: list[str]) -> str:
    import hashlib

    return hashlib.md5(",".join(values).encode("utf-8")).hexdigest()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        sys.exit(1)
