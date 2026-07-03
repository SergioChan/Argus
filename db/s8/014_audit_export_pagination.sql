BEGIN;

CREATE OR REPLACE FUNCTION s8.export_audit_slice(
    p_artifact_ids text[],
    p_page_size integer,
    p_page_token integer
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = s8, pg_temp
AS $$
DECLARE
    latest_checkpoint s8.merkle_checkpoint%ROWTYPE;
    missing_refs text[];
    page_offset integer := COALESCE(p_page_token, 0);
    total_count integer;
BEGIN
    IF p_page_size IS NOT NULL AND p_page_size <= 0 THEN
        RAISE EXCEPTION 'page_size must be positive'
            USING ERRCODE = '22023';
    END IF;

    IF page_offset < 0 THEN
        RAISE EXCEPTION 'page_token must be non-negative'
            USING ERRCODE = '22023';
    END IF;

    SELECT *
    INTO latest_checkpoint
    FROM s8.merkle_checkpoint
    ORDER BY seq DESC
    LIMIT 1;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'no merkle checkpoint available for audit export'
            USING ERRCODE = '23503';
    END IF;

    IF p_artifact_ids IS NOT NULL THEN
        SELECT array_agg(requested.ref ORDER BY requested.ref)
        INTO missing_refs
        FROM unnest(p_artifact_ids) AS requested(ref)
        WHERE NOT EXISTS (
            SELECT 1
            FROM s8.ledger_leaf AS leaf
            WHERE leaf.artifact_id = requested.ref
              AND leaf.sequence <= latest_checkpoint.seq
        );

        IF missing_refs IS NOT NULL THEN
            RAISE EXCEPTION 'audit export missing ledger leaves for %', missing_refs
                USING ERRCODE = '23503';
        END IF;
    END IF;

    SELECT count(*)
    INTO total_count
    FROM s8.ledger_leaf AS leaf
    WHERE leaf.sequence <= latest_checkpoint.seq
      AND (p_artifact_ids IS NULL OR leaf.artifact_id = ANY(p_artifact_ids));

    RETURN jsonb_build_object(
        'records',
        (
            WITH paged AS (
                SELECT leaf.*
                FROM s8.ledger_leaf AS leaf
                WHERE leaf.sequence <= latest_checkpoint.seq
                  AND (p_artifact_ids IS NULL OR leaf.artifact_id = ANY(p_artifact_ids))
                ORDER BY leaf.sequence
                LIMIT p_page_size
                OFFSET page_offset
            )
            SELECT COALESCE(
                jsonb_agg(
                    jsonb_build_object(
                        'artifact_id', record.artifact_id,
                        'content_hash', record.content_hash,
                        'kind', record.kind,
                        'producer', record.producer,
                        'lineage', record.lineage,
                        'claim_tier', record.claim_tier,
                        'validation_report_ref', record.validation_report_ref,
                        'record_hash', record.record_hash,
                        'merkle_seq', record.merkle_seq,
                        'created_at', record.created_at
                    )
                    ORDER BY paged.sequence
                ),
                '[]'::jsonb
            )
            FROM paged
            JOIN s8.artifact_record AS record
              ON record.artifact_id = paged.artifact_id
        ),
        'leaves',
        (
            WITH paged AS (
                SELECT leaf.*
                FROM s8.ledger_leaf AS leaf
                WHERE leaf.sequence <= latest_checkpoint.seq
                  AND (p_artifact_ids IS NULL OR leaf.artifact_id = ANY(p_artifact_ids))
                ORDER BY leaf.sequence
                LIMIT p_page_size
                OFFSET page_offset
            )
            SELECT COALESCE(
                jsonb_agg(
                    jsonb_build_object(
                        'sequence', paged.sequence,
                        'artifact_id', paged.artifact_id,
                        'record_hash', paged.record_hash,
                        'previous_root', paged.previous_root,
                        'root', paged.root
                    )
                    ORDER BY paged.sequence
                ),
                '[]'::jsonb
            )
            FROM paged
        ),
        'merkle_checkpoints',
        jsonb_build_array(
            jsonb_build_object(
                'sequence', latest_checkpoint.seq,
                'root', latest_checkpoint.root,
                'signature', latest_checkpoint.signature,
                'signer_key_id', latest_checkpoint.signer_key_id,
                'created_at', latest_checkpoint.created_at
            )
        ),
        'inclusion_proofs',
        (
            WITH paged AS (
                SELECT leaf.*
                FROM s8.ledger_leaf AS leaf
                WHERE leaf.sequence <= latest_checkpoint.seq
                  AND (p_artifact_ids IS NULL OR leaf.artifact_id = ANY(p_artifact_ids))
                ORDER BY leaf.sequence
                LIMIT p_page_size
                OFFSET page_offset
            )
            SELECT COALESCE(
                jsonb_agg(
                    jsonb_build_object(
                        'artifact_id', selected.artifact_id,
                        'sequence', selected.sequence,
                        'record_hash', selected.record_hash,
                        'anchor_previous_root', selected.previous_root,
                        'steps',
                        (
                            SELECT COALESCE(
                                jsonb_agg(
                                    jsonb_build_object(
                                        'sequence', suffix.sequence,
                                        'artifact_id', suffix.artifact_id,
                                        'record_hash', suffix.record_hash,
                                        'previous_root', suffix.previous_root,
                                        'root', suffix.root
                                    )
                                    ORDER BY suffix.sequence
                                ),
                                '[]'::jsonb
                            )
                            FROM s8.ledger_leaf AS suffix
                            WHERE suffix.sequence > selected.sequence
                              AND suffix.sequence <= latest_checkpoint.seq
                        )
                    )
                    ORDER BY selected.sequence
                ),
                '[]'::jsonb
            )
            FROM paged AS selected
        ),
        'next_page_token',
        CASE
            WHEN p_page_size IS NOT NULL AND page_offset + p_page_size < total_count
                THEN page_offset + p_page_size
            ELSE NULL
        END
    );
END;
$$;

REVOKE ALL ON FUNCTION s8.export_audit_slice(text[], integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION s8.export_audit_slice(text[], integer, integer)
TO argus_s8_reader, argus_s8_ledger_writer;

COMMIT;
