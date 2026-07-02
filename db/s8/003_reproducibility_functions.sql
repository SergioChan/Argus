BEGIN;

CREATE OR REPLACE FUNCTION s8.get_reproducibility_manifest(p_artifact_id text)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = s8, pg_temp
AS $$
    SELECT jsonb_build_object(
        'artifact_id', record.artifact_id,
        'content_hash', record.content_hash,
        'kind', record.kind,
        'producer', record.producer,
        'lineage', record.lineage,
        'claim_tier', record.claim_tier,
        'validation_report_ref', record.validation_report_ref,
        'created_at', record.created_at
    )
    FROM s8.artifact_record AS record
    WHERE record.artifact_id = p_artifact_id;
$$;

CREATE OR REPLACE FUNCTION s8.record_reproducibility_check(
    p_check_id text,
    p_artifact_id text,
    p_rerun_content_hash text,
    p_verdict text,
    p_tolerance_id text DEFAULT NULL
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = s8, pg_temp
AS $$
DECLARE
    existing_check s8.reproducibility_check%ROWTYPE;
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM s8.artifact_record
        WHERE artifact_id = p_artifact_id
    ) THEN
        RAISE EXCEPTION 'artifact record % does not exist', p_artifact_id
            USING ERRCODE = '23503';
    END IF;

    SELECT *
    INTO existing_check
    FROM s8.reproducibility_check
    WHERE check_id = p_check_id;

    IF FOUND THEN
        IF existing_check.artifact_id = p_artifact_id
           AND existing_check.rerun_content_hash = p_rerun_content_hash
           AND existing_check.verdict = p_verdict
           AND existing_check.tolerance_id IS NOT DISTINCT FROM p_tolerance_id THEN
            RETURN FALSE;
        END IF;

        RAISE EXCEPTION 'reproducibility check % already exists with different payload', p_check_id
            USING ERRCODE = '23505';
    END IF;

    INSERT INTO s8.reproducibility_check (
        check_id,
        artifact_id,
        rerun_content_hash,
        verdict,
        tolerance_id
    ) VALUES (
        p_check_id,
        p_artifact_id,
        p_rerun_content_hash,
        p_verdict,
        p_tolerance_id
    );

    RETURN TRUE;
END;
$$;

REVOKE INSERT ON s8.reproducibility_check FROM argus_s8_ledger_writer;

REVOKE ALL ON FUNCTION s8.get_reproducibility_manifest(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION s8.get_reproducibility_manifest(text)
TO argus_s8_reader, argus_s8_ledger_writer;

REVOKE ALL ON FUNCTION s8.record_reproducibility_check(text, text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION s8.record_reproducibility_check(text, text, text, text, text)
TO argus_s8_ledger_writer;

COMMIT;
