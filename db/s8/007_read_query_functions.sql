BEGIN;

CREATE INDEX IF NOT EXISTS artifact_record_kind_idx
    ON s8.artifact_record (kind);

CREATE INDEX IF NOT EXISTS artifact_record_claim_tier_idx
    ON s8.artifact_record (claim_tier);

CREATE INDEX IF NOT EXISTS artifact_record_producer_subsystem_idx
    ON s8.artifact_record ((producer->>'subsystem'));

CREATE INDEX IF NOT EXISTS artifact_record_producer_version_idx
    ON s8.artifact_record ((producer->>'version'));

CREATE INDEX IF NOT EXISTS artifact_record_actor_id_idx
    ON s8.artifact_record ((COALESCE(producer->>'actor_id', lineage->>'actor_id')));

CREATE INDEX IF NOT EXISTS artifact_record_job_id_idx
    ON s8.artifact_record ((COALESCE(producer->>'job_id', lineage->>'job_id')));

CREATE INDEX IF NOT EXISTS artifact_record_contamination_index_version_idx
    ON s8.artifact_record ((lineage->>'contamination_index_version'));

CREATE INDEX IF NOT EXISTS artifact_record_created_at_idx
    ON s8.artifact_record (created_at);

CREATE OR REPLACE FUNCTION s8.artifact_record_to_json(p_record s8.artifact_record)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = s8, pg_temp
AS $$
    SELECT jsonb_build_object(
        'artifact_id', p_record.artifact_id,
        'artifact_ref', p_record.artifact_id,
        'content_hash', p_record.content_hash,
        'kind', p_record.kind,
        'producer', p_record.producer,
        'lineage', p_record.lineage,
        'claim_tier', p_record.claim_tier,
        'validation_report_ref', p_record.validation_report_ref,
        'record_hash', p_record.record_hash,
        'merkle_seq', p_record.merkle_seq,
        'created_at', p_record.created_at
    );
$$;

CREATE OR REPLACE FUNCTION s8.get_artifact_record(p_ref text)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = s8, pg_temp
AS $$
DECLARE
    resolved_record s8.artifact_record%ROWTYPE;
BEGIN
    IF COALESCE(p_ref, '') = '' THEN
        RAISE EXCEPTION 'artifact ref is required'
            USING ERRCODE = '23514';
    END IF;

    SELECT *
    INTO resolved_record
    FROM s8.artifact_record
    WHERE artifact_id = p_ref;

    IF NOT FOUND THEN
        SELECT *
        INTO resolved_record
        FROM s8.artifact_record
        WHERE content_hash = p_ref;
    END IF;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'artifact record % not found', p_ref
            USING ERRCODE = '23503';
    END IF;

    RETURN s8.artifact_record_to_json(resolved_record);
END;
$$;

CREATE OR REPLACE FUNCTION s8.query_artifacts(
    p_filter jsonb DEFAULT '{}'::jsonb,
    p_limit integer DEFAULT 100,
    p_offset integer DEFAULT 0
)
RETURNS SETOF jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = s8, pg_temp
AS $$
DECLARE
    normalized_filter jsonb := COALESCE(p_filter, '{}'::jsonb);
BEGIN
    IF jsonb_typeof(normalized_filter) <> 'object' THEN
        RAISE EXCEPTION 'artifact query filter must be a JSON object'
            USING ERRCODE = '23514';
    END IF;

    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 1000 THEN
        RAISE EXCEPTION 'artifact query limit must be between 1 and 1000'
            USING ERRCODE = '23514';
    END IF;

    IF p_offset IS NULL OR p_offset < 0 THEN
        RAISE EXCEPTION 'artifact query offset must be non-negative'
            USING ERRCODE = '23514';
    END IF;

    RETURN QUERY
    SELECT s8.artifact_record_to_json(record)
    FROM s8.artifact_record AS record
    WHERE (NOT normalized_filter ? 'artifact_id' OR record.artifact_id = normalized_filter->>'artifact_id')
      AND (NOT normalized_filter ? 'artifact_ref' OR record.artifact_id = normalized_filter->>'artifact_ref')
      AND (NOT normalized_filter ? 'content_hash' OR record.content_hash = normalized_filter->>'content_hash')
      AND (NOT normalized_filter ? 'kind' OR record.kind = normalized_filter->>'kind')
      AND (NOT normalized_filter ? 'claim_tier' OR record.claim_tier = normalized_filter->>'claim_tier')
      AND (
          NOT normalized_filter ? 'validation_report_ref'
          OR record.validation_report_ref IS NOT DISTINCT FROM normalized_filter->>'validation_report_ref'
      )
      AND (NOT normalized_filter ? 'producer_subsystem' OR record.producer->>'subsystem' = normalized_filter->>'producer_subsystem')
      AND (NOT normalized_filter ? 'producer_version' OR record.producer->>'version' = normalized_filter->>'producer_version')
      AND (
          NOT normalized_filter ? 'actor_id'
          OR COALESCE(record.producer->>'actor_id', record.lineage->>'actor_id') = normalized_filter->>'actor_id'
      )
      AND (
          NOT normalized_filter ? 'job_id'
          OR COALESCE(record.producer->>'job_id', record.lineage->>'job_id') = normalized_filter->>'job_id'
      )
      AND (
          NOT normalized_filter ? 'contamination_index_version'
          OR record.lineage->>'contamination_index_version' = normalized_filter->>'contamination_index_version'
      )
      AND (
          NOT normalized_filter ? 'created_after'
          OR record.created_at >= (normalized_filter->>'created_after')::timestamptz
      )
      AND (
          NOT normalized_filter ? 'created_before'
          OR record.created_at <= (normalized_filter->>'created_before')::timestamptz
      )
    ORDER BY record.merkle_seq, record.artifact_id
    LIMIT p_limit
    OFFSET p_offset;
END;
$$;

REVOKE ALL ON FUNCTION s8.artifact_record_to_json(s8.artifact_record) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION s8.artifact_record_to_json(s8.artifact_record)
TO argus_s8_reader, argus_s8_ledger_writer;

REVOKE ALL ON FUNCTION s8.get_artifact_record(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION s8.get_artifact_record(text)
TO argus_s8_reader, argus_s8_ledger_writer;

REVOKE ALL ON FUNCTION s8.query_artifacts(jsonb, integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION s8.query_artifacts(jsonb, integer, integer)
TO argus_s8_reader, argus_s8_ledger_writer;

COMMIT;
