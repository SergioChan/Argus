BEGIN;

CREATE SCHEMA IF NOT EXISTS s8;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'argus_s8_reader') THEN
        CREATE ROLE argus_s8_reader NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'argus_s8_ledger_writer') THEN
        CREATE ROLE argus_s8_ledger_writer NOLOGIN;
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS s8.artifact_record (
    artifact_id text PRIMARY KEY,
    content_hash text NOT NULL UNIQUE,
    kind text NOT NULL,
    producer jsonb NOT NULL,
    lineage jsonb NOT NULL,
    claim_tier text NOT NULL DEFAULT 'ran-toy',
    validation_report_ref text,
    record_hash text NOT NULL UNIQUE,
    merkle_seq bigint NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS s8.lineage_edge (
    edge_id bigserial PRIMARY KEY,
    src_artifact_id text NOT NULL REFERENCES s8.artifact_record(artifact_id),
    dst_artifact_id text NOT NULL REFERENCES s8.artifact_record(artifact_id),
    edge_type text NOT NULL CHECK (edge_type IN ('input', 'derived_from', 'code', 'adapter_used', 'validation_report')),
    role text,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (src_artifact_id, dst_artifact_id, edge_type, role)
);

CREATE TABLE IF NOT EXISTS s8.lineage_closure (
    ancestor_id text NOT NULL REFERENCES s8.artifact_record(artifact_id),
    descendant_id text NOT NULL REFERENCES s8.artifact_record(artifact_id),
    depth integer NOT NULL CHECK (depth >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (ancestor_id, descendant_id)
);

CREATE TABLE IF NOT EXISTS s8.external_source (
    source_id text PRIMARY KEY,
    source text NOT NULL,
    external_id text NOT NULL,
    url text NOT NULL,
    snapshot_hash text NOT NULL,
    license text NOT NULL,
    ingested_at timestamptz NOT NULL,
    artifact_id text NOT NULL REFERENCES s8.artifact_record(artifact_id),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (source, external_id)
);

CREATE TABLE IF NOT EXISTS s8.merkle_checkpoint (
    seq bigint PRIMARY KEY,
    root text NOT NULL,
    signature text NOT NULL,
    signer_key_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS s8.reproducibility_check (
    check_id text PRIMARY KEY,
    artifact_id text NOT NULL REFERENCES s8.artifact_record(artifact_id),
    rerun_content_hash text NOT NULL,
    verdict text NOT NULL CHECK (verdict IN ('PASS', 'FAIL', 'INCONCLUSIVE')),
    tolerance_id text,
    checked_at timestamptz NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION s8.reject_append_only_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'append-only table % cannot be updated or deleted', TG_TABLE_NAME
        USING ERRCODE = '55000';
END;
$$;

CREATE OR REPLACE FUNCTION s8.insert_lineage_edge(
    p_src_artifact_id text,
    p_dst_artifact_id text,
    p_edge_type text,
    p_role text DEFAULT NULL
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = s8, pg_temp
AS $$
DECLARE
    inserted_edge_id bigint;
BEGIN
    IF p_src_artifact_id = p_dst_artifact_id THEN
        RAISE EXCEPTION 'lineage cycle detected through %', p_src_artifact_id
            USING ERRCODE = '23P01';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM s8.lineage_closure
        WHERE ancestor_id = p_dst_artifact_id
          AND descendant_id = p_src_artifact_id
    ) THEN
        RAISE EXCEPTION 'lineage cycle detected through % -> %', p_src_artifact_id, p_dst_artifact_id
            USING ERRCODE = '23P01';
    END IF;

    INSERT INTO s8.lineage_edge (src_artifact_id, dst_artifact_id, edge_type, role)
    SELECT p_src_artifact_id, p_dst_artifact_id, p_edge_type, p_role
    WHERE NOT EXISTS (
        SELECT 1
        FROM s8.lineage_edge
        WHERE src_artifact_id = p_src_artifact_id
          AND dst_artifact_id = p_dst_artifact_id
          AND edge_type = p_edge_type
          AND COALESCE(role, '') = COALESCE(p_role, '')
    )
    RETURNING edge_id INTO inserted_edge_id;

    INSERT INTO s8.lineage_closure (ancestor_id, descendant_id, depth)
    SELECT ancestor_id, descendant_id, min(depth)
    FROM (
        SELECT
            ancestors.ancestor_id,
            descendants.descendant_id,
            ancestors.depth + 1 + descendants.depth AS depth
        FROM (
            SELECT p_src_artifact_id AS ancestor_id, 0 AS depth
            UNION ALL
            SELECT ancestor_id, depth
            FROM s8.lineage_closure
            WHERE descendant_id = p_src_artifact_id
        ) AS ancestors
        CROSS JOIN (
            SELECT p_dst_artifact_id AS descendant_id, 0 AS depth
            UNION ALL
            SELECT descendant_id, depth
            FROM s8.lineage_closure
            WHERE ancestor_id = p_dst_artifact_id
        ) AS descendants
    ) AS closure_paths
    GROUP BY ancestor_id, descendant_id
    ON CONFLICT (ancestor_id, descendant_id) DO NOTHING;

    RETURN inserted_edge_id;
END;
$$;

DROP TRIGGER IF EXISTS artifact_record_append_only ON s8.artifact_record;
CREATE TRIGGER artifact_record_append_only
    BEFORE UPDATE OR DELETE ON s8.artifact_record
    FOR EACH STATEMENT EXECUTE FUNCTION s8.reject_append_only_mutation();

DROP TRIGGER IF EXISTS lineage_edge_append_only ON s8.lineage_edge;
CREATE TRIGGER lineage_edge_append_only
    BEFORE UPDATE OR DELETE ON s8.lineage_edge
    FOR EACH STATEMENT EXECUTE FUNCTION s8.reject_append_only_mutation();

DROP TRIGGER IF EXISTS lineage_closure_append_only ON s8.lineage_closure;
CREATE TRIGGER lineage_closure_append_only
    BEFORE UPDATE OR DELETE ON s8.lineage_closure
    FOR EACH STATEMENT EXECUTE FUNCTION s8.reject_append_only_mutation();

DROP TRIGGER IF EXISTS external_source_append_only ON s8.external_source;
CREATE TRIGGER external_source_append_only
    BEFORE UPDATE OR DELETE ON s8.external_source
    FOR EACH STATEMENT EXECUTE FUNCTION s8.reject_append_only_mutation();

DROP TRIGGER IF EXISTS merkle_checkpoint_append_only ON s8.merkle_checkpoint;
CREATE TRIGGER merkle_checkpoint_append_only
    BEFORE UPDATE OR DELETE ON s8.merkle_checkpoint
    FOR EACH STATEMENT EXECUTE FUNCTION s8.reject_append_only_mutation();

DROP TRIGGER IF EXISTS reproducibility_check_append_only ON s8.reproducibility_check;
CREATE TRIGGER reproducibility_check_append_only
    BEFORE UPDATE OR DELETE ON s8.reproducibility_check
    FOR EACH STATEMENT EXECUTE FUNCTION s8.reject_append_only_mutation();

REVOKE ALL ON SCHEMA s8 FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA s8 FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA s8 FROM PUBLIC;

GRANT USAGE ON SCHEMA s8 TO argus_s8_reader, argus_s8_ledger_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA s8 TO argus_s8_reader, argus_s8_ledger_writer;

GRANT INSERT ON
    s8.artifact_record,
    s8.external_source,
    s8.merkle_checkpoint,
    s8.reproducibility_check
TO argus_s8_ledger_writer;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA s8 TO argus_s8_ledger_writer;
REVOKE ALL ON FUNCTION s8.insert_lineage_edge(text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION s8.insert_lineage_edge(text, text, text, text) TO argus_s8_ledger_writer;

COMMIT;
