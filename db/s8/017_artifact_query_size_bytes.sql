BEGIN;

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
        'size_bytes', p_record.size_bytes,
        'producer', p_record.producer,
        'lineage', p_record.lineage,
        'claim_tier', p_record.claim_tier,
        'validation_report_ref', p_record.validation_report_ref,
        'record_hash', p_record.record_hash,
        'merkle_seq', p_record.merkle_seq,
        'created_at', p_record.created_at
    );
$$;

REVOKE ALL ON FUNCTION s8.artifact_record_to_json(s8.artifact_record) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION s8.artifact_record_to_json(s8.artifact_record)
TO argus_s8_reader, argus_s8_ledger_writer;

COMMIT;
