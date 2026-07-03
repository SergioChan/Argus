BEGIN;

CREATE OR REPLACE FUNCTION s8.get_reproducibility_status(p_artifact_id text)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = s8, pg_temp
AS $$
    WITH requested AS (
        SELECT p_artifact_id AS artifact_id
    ),
    artifact AS (
        SELECT artifact_id
        FROM s8.artifact_record
        WHERE artifact_id = p_artifact_id
    ),
    summary AS (
        SELECT
            count(*)::integer AS check_count,
            count(*) FILTER (WHERE verdict = 'FAIL')::integer AS failed_check_count
        FROM s8.reproducibility_check
        WHERE artifact_id = p_artifact_id
    ),
    latest AS (
        SELECT check_id, verdict
        FROM s8.reproducibility_check
        WHERE artifact_id = p_artifact_id
        ORDER BY checked_at DESC, check_id DESC
        LIMIT 1
    )
    SELECT CASE
        WHEN artifact.artifact_id IS NULL THEN NULL
        ELSE jsonb_build_object(
            'artifact_id', artifact.artifact_id,
            'artifact_ref', artifact.artifact_id,
            'non_reproducible', COALESCE(summary.failed_check_count, 0) > 0,
            'non_promotable', COALESCE(summary.failed_check_count, 0) > 0,
            'check_count', COALESCE(summary.check_count, 0),
            'failed_check_count', COALESCE(summary.failed_check_count, 0),
            'latest_check_id', latest.check_id,
            'latest_verdict', latest.verdict
        )
    END
    FROM requested
    LEFT JOIN artifact ON artifact.artifact_id = requested.artifact_id
    LEFT JOIN summary ON TRUE
    LEFT JOIN latest ON TRUE;
$$;

REVOKE ALL ON FUNCTION s8.get_reproducibility_status(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION s8.get_reproducibility_status(text)
TO argus_s8_reader, argus_s8_ledger_writer;

COMMIT;
