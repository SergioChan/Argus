BEGIN;

ALTER TABLE s8.artifact_record
ADD COLUMN IF NOT EXISTS size_bytes bigint;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'artifact_record_size_bytes_nonnegative'
          AND conrelid = 's8.artifact_record'::regclass
    ) THEN
        ALTER TABLE s8.artifact_record
        ADD CONSTRAINT artifact_record_size_bytes_nonnegative
        CHECK (size_bytes IS NULL OR size_bytes >= 0) NOT VALID;
    END IF;
END
$$;

ALTER TABLE s8.artifact_record
VALIDATE CONSTRAINT artifact_record_size_bytes_nonnegative;

DROP FUNCTION IF EXISTS s8.commit_artifact_record(
    text, text, text, jsonb, jsonb, text, bigint, text, text, text[], timestamptz
);

CREATE OR REPLACE FUNCTION s8.commit_artifact_record(
    p_artifact_id text,
    p_content_hash text,
    p_kind text,
    p_producer jsonb,
    p_lineage jsonb,
    p_record_hash text,
    p_merkle_seq bigint,
    p_claim_tier text DEFAULT 'ran-toy',
    p_validation_report_ref text DEFAULT NULL,
    p_input_refs text[] DEFAULT ARRAY[]::text[],
    p_created_at timestamptz DEFAULT NULL,
    p_size_bytes bigint DEFAULT NULL
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = s8, pg_temp
AS $$
DECLARE
    existing_record s8.artifact_record%ROWTYPE;
    input_ref text;
    normalized_claim_tier text := COALESCE(p_claim_tier, 'ran-toy');
    normalized_input_refs text[] := COALESCE(p_input_refs, ARRAY[]::text[]);
    normalized_created_at timestamptz := COALESCE(p_created_at, now());
BEGIN
    IF p_size_bytes IS NOT NULL AND p_size_bytes < 0 THEN
        RAISE EXCEPTION 'artifact record % has negative size_bytes', p_artifact_id
            USING ERRCODE = '23514';
    END IF;

    SELECT *
    INTO existing_record
    FROM s8.artifact_record
    WHERE artifact_id = p_artifact_id;

    IF FOUND THEN
        IF existing_record.content_hash = p_content_hash
           AND existing_record.kind = p_kind
           AND existing_record.producer = p_producer
           AND existing_record.lineage = p_lineage
           AND existing_record.claim_tier = normalized_claim_tier
           AND existing_record.validation_report_ref IS NOT DISTINCT FROM p_validation_report_ref
           AND existing_record.record_hash = p_record_hash
           AND existing_record.merkle_seq = p_merkle_seq
           AND (p_created_at IS NULL OR existing_record.created_at = normalized_created_at)
           AND (p_size_bytes IS NULL OR existing_record.size_bytes IS NOT DISTINCT FROM p_size_bytes) THEN
            RETURN FALSE;
        END IF;

        RAISE EXCEPTION 'artifact record % already exists with different payload', p_artifact_id
            USING ERRCODE = '23505';
    END IF;

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
        created_at,
        size_bytes
    ) VALUES (
        p_artifact_id,
        p_content_hash,
        p_kind,
        p_producer,
        p_lineage,
        normalized_claim_tier,
        p_validation_report_ref,
        p_record_hash,
        p_merkle_seq,
        normalized_created_at,
        p_size_bytes
    );

    FOREACH input_ref IN ARRAY normalized_input_refs LOOP
        PERFORM s8.insert_lineage_edge(input_ref, p_artifact_id, 'input', NULL);
    END LOOP;

    IF p_validation_report_ref IS NOT NULL THEN
        PERFORM s8.insert_lineage_edge(p_validation_report_ref, p_artifact_id, 'validation_report', NULL);
    END IF;

    RETURN TRUE;
END;
$$;

REVOKE ALL ON FUNCTION s8.commit_artifact_record(
    text, text, text, jsonb, jsonb, text, bigint, text, text, text[], timestamptz, bigint
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION s8.commit_artifact_record(
    text, text, text, jsonb, jsonb, text, bigint, text, text, text[], timestamptz, bigint
) TO argus_s8_ledger_writer;

COMMIT;
