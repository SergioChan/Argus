BEGIN;

CREATE OR REPLACE FUNCTION s8.export_audit_slice(
    p_artifact_ids text[] DEFAULT NULL
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
BEGIN
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

    RETURN jsonb_build_object(
        'records',
        (
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
                    ORDER BY leaf.sequence
                ),
                '[]'::jsonb
            )
            FROM s8.ledger_leaf AS leaf
            JOIN s8.artifact_record AS record
              ON record.artifact_id = leaf.artifact_id
            WHERE leaf.sequence <= latest_checkpoint.seq
              AND (p_artifact_ids IS NULL OR leaf.artifact_id = ANY(p_artifact_ids))
        ),
        'leaves',
        (
            SELECT COALESCE(
                jsonb_agg(
                    jsonb_build_object(
                        'sequence', leaf.sequence,
                        'artifact_id', leaf.artifact_id,
                        'record_hash', leaf.record_hash,
                        'previous_root', leaf.previous_root,
                        'root', leaf.root
                    )
                    ORDER BY leaf.sequence
                ),
                '[]'::jsonb
            )
            FROM s8.ledger_leaf AS leaf
            WHERE leaf.sequence <= latest_checkpoint.seq
              AND (p_artifact_ids IS NULL OR leaf.artifact_id = ANY(p_artifact_ids))
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
            FROM s8.ledger_leaf AS selected
            WHERE selected.sequence <= latest_checkpoint.seq
              AND (p_artifact_ids IS NULL OR selected.artifact_id = ANY(p_artifact_ids))
        )
    );
END;
$$;

CREATE OR REPLACE FUNCTION s8.verify_audit_chain()
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = s8, pg_temp
AS $$
DECLARE
    leaf s8.ledger_leaf%ROWTYPE;
    latest_checkpoint s8.merkle_checkpoint%ROWTYPE;
    expected_sequence bigint := 1;
    previous_root text := 'blake3:' || repeat('0', 64);
    stored_record_hash text;
BEGIN
    FOR leaf IN
        SELECT *
        FROM s8.ledger_leaf
        ORDER BY sequence
    LOOP
        IF leaf.sequence <> expected_sequence THEN
            RETURN jsonb_build_object(
                'valid', false,
                'break_sequence', leaf.sequence,
                'reason', 'sequence_gap'
            );
        END IF;

        IF leaf.previous_root <> previous_root THEN
            RETURN jsonb_build_object(
                'valid', false,
                'break_sequence', leaf.sequence,
                'reason', 'previous_root_mismatch'
            );
        END IF;

        SELECT record_hash
        INTO stored_record_hash
        FROM s8.artifact_record
        WHERE artifact_id = leaf.artifact_id;

        IF NOT FOUND OR stored_record_hash <> leaf.record_hash THEN
            RETURN jsonb_build_object(
                'valid', false,
                'break_sequence', leaf.sequence,
                'reason', 'record_hash_mismatch'
            );
        END IF;

        expected_sequence := expected_sequence + 1;
        previous_root := leaf.root;
    END LOOP;

    IF expected_sequence = 1 THEN
        RETURN jsonb_build_object(
            'valid', true,
            'break_sequence', NULL,
            'reason', NULL,
            'checkpoint_sequence', 0
        );
    END IF;

    SELECT *
    INTO latest_checkpoint
    FROM s8.merkle_checkpoint
    ORDER BY seq DESC
    LIMIT 1;

    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'valid', false,
            'break_sequence', expected_sequence - 1,
            'reason', 'checkpoint_missing'
        );
    END IF;

    IF latest_checkpoint.seq <> expected_sequence - 1 OR latest_checkpoint.root <> previous_root THEN
        RETURN jsonb_build_object(
            'valid', false,
            'break_sequence', latest_checkpoint.seq,
            'reason', 'checkpoint_mismatch'
        );
    END IF;

    IF latest_checkpoint.signature NOT LIKE 'hmac-sha256:%' THEN
        RETURN jsonb_build_object(
            'valid', false,
            'break_sequence', latest_checkpoint.seq,
            'reason', 'checkpoint_signature_unsupported'
        );
    END IF;

    RETURN jsonb_build_object(
        'valid', true,
        'break_sequence', NULL,
        'reason', NULL,
        'checkpoint_sequence', latest_checkpoint.seq
    );
END;
$$;

CREATE OR REPLACE FUNCTION s8.verify_audit_slice(p_slice jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = s8, pg_temp
AS $$
DECLARE
    checkpoint_payload jsonb;
    checkpoint_sequence bigint;
    checkpoint_root text;
    checkpoint_signature text;
    checkpoint_signer_key_id text;
    db_checkpoint s8.merkle_checkpoint%ROWTYPE;
    leaf_payload jsonb;
    leaf_sequence bigint;
    leaf_artifact_id text;
    leaf_record_hash text;
    leaf_previous_root text;
    leaf_root text;
    db_leaf s8.ledger_leaf%ROWTYPE;
    db_record_hash text;
    proof_payload jsonb;
    step_payload jsonb;
    step_sequence bigint;
    current_sequence bigint;
    current_root text;
BEGIN
    IF p_slice IS NULL OR jsonb_typeof(p_slice) <> 'object' THEN
        RETURN jsonb_build_object('valid', false, 'break_sequence', NULL, 'reason', 'slice_not_object');
    END IF;

    SELECT checkpoint.value
    INTO checkpoint_payload
    FROM jsonb_array_elements(COALESCE(p_slice->'merkle_checkpoints', '[]'::jsonb)) AS checkpoint(value)
    ORDER BY (checkpoint.value->>'sequence')::bigint DESC
    LIMIT 1;

    IF checkpoint_payload IS NULL THEN
        RETURN jsonb_build_object('valid', false, 'break_sequence', NULL, 'reason', 'checkpoint_missing');
    END IF;

    checkpoint_sequence := (checkpoint_payload->>'sequence')::bigint;
    checkpoint_root := checkpoint_payload->>'root';
    checkpoint_signature := checkpoint_payload->>'signature';
    checkpoint_signer_key_id := checkpoint_payload->>'signer_key_id';

    SELECT *
    INTO db_checkpoint
    FROM s8.merkle_checkpoint
    WHERE seq = checkpoint_sequence;

    IF NOT FOUND
       OR db_checkpoint.root <> checkpoint_root
       OR db_checkpoint.signature <> checkpoint_signature
       OR db_checkpoint.signer_key_id <> checkpoint_signer_key_id THEN
        RETURN jsonb_build_object(
            'valid', false,
            'break_sequence', checkpoint_sequence,
            'reason', 'checkpoint_mismatch'
        );
    END IF;

    FOR leaf_payload IN
        SELECT leaf.value
        FROM jsonb_array_elements(COALESCE(p_slice->'leaves', '[]'::jsonb)) AS leaf(value)
        ORDER BY (leaf.value->>'sequence')::bigint
    LOOP
        leaf_sequence := (leaf_payload->>'sequence')::bigint;
        leaf_artifact_id := leaf_payload->>'artifact_id';
        leaf_record_hash := leaf_payload->>'record_hash';
        leaf_previous_root := leaf_payload->>'previous_root';
        leaf_root := leaf_payload->>'root';

        SELECT *
        INTO db_leaf
        FROM s8.ledger_leaf
        WHERE sequence = leaf_sequence;

        IF NOT FOUND
           OR db_leaf.artifact_id <> leaf_artifact_id
           OR db_leaf.record_hash <> leaf_record_hash
           OR db_leaf.previous_root <> leaf_previous_root
           OR db_leaf.root <> leaf_root THEN
            RETURN jsonb_build_object(
                'valid', false,
                'break_sequence', leaf_sequence,
                'reason', 'leaf_mismatch'
            );
        END IF;

        SELECT record_hash
        INTO db_record_hash
        FROM s8.artifact_record
        WHERE artifact_id = leaf_artifact_id;

        IF NOT FOUND OR db_record_hash <> leaf_record_hash THEN
            RETURN jsonb_build_object(
                'valid', false,
                'break_sequence', leaf_sequence,
                'reason', 'record_hash_mismatch'
            );
        END IF;

        SELECT proof.value
        INTO proof_payload
        FROM jsonb_array_elements(COALESCE(p_slice->'inclusion_proofs', '[]'::jsonb)) AS proof(value)
        WHERE (proof.value->>'sequence')::bigint = leaf_sequence
        LIMIT 1;

        IF proof_payload IS NULL
           OR (proof_payload->>'artifact_id') <> leaf_artifact_id
           OR (proof_payload->>'record_hash') <> leaf_record_hash
           OR (proof_payload->>'anchor_previous_root') <> leaf_previous_root THEN
            RETURN jsonb_build_object(
                'valid', false,
                'break_sequence', leaf_sequence,
                'reason', 'proof_mismatch'
            );
        END IF;

        current_sequence := leaf_sequence;
        current_root := leaf_root;

        FOR step_payload IN
            SELECT step.value
            FROM jsonb_array_elements(COALESCE(proof_payload->'steps', '[]'::jsonb)) AS step(value)
            ORDER BY (step.value->>'sequence')::bigint
        LOOP
            step_sequence := (step_payload->>'sequence')::bigint;

            IF step_sequence <> current_sequence + 1
               OR (step_payload->>'previous_root') <> current_root THEN
                RETURN jsonb_build_object(
                    'valid', false,
                    'break_sequence', step_sequence,
                    'reason', 'proof_step_mismatch'
                );
            END IF;

            SELECT *
            INTO db_leaf
            FROM s8.ledger_leaf
            WHERE sequence = step_sequence;

            IF NOT FOUND
               OR db_leaf.artifact_id <> (step_payload->>'artifact_id')
               OR db_leaf.record_hash <> (step_payload->>'record_hash')
               OR db_leaf.previous_root <> (step_payload->>'previous_root')
               OR db_leaf.root <> (step_payload->>'root') THEN
                RETURN jsonb_build_object(
                    'valid', false,
                    'break_sequence', step_sequence,
                    'reason', 'proof_step_db_mismatch'
                );
            END IF;

            current_sequence := step_sequence;
            current_root := step_payload->>'root';
        END LOOP;

        IF current_sequence <> checkpoint_sequence OR current_root <> checkpoint_root THEN
            RETURN jsonb_build_object(
                'valid', false,
                'break_sequence', checkpoint_sequence,
                'reason', 'proof_checkpoint_mismatch'
            );
        END IF;
    END LOOP;

    RETURN jsonb_build_object(
        'valid', true,
        'break_sequence', NULL,
        'reason', NULL,
        'checkpoint_sequence', checkpoint_sequence
    );
END;
$$;

REVOKE ALL ON FUNCTION s8.export_audit_slice(text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION s8.export_audit_slice(text[])
TO argus_s8_reader, argus_s8_ledger_writer;

REVOKE ALL ON FUNCTION s8.verify_audit_chain() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION s8.verify_audit_chain()
TO argus_s8_reader, argus_s8_ledger_writer;

REVOKE ALL ON FUNCTION s8.verify_audit_slice(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION s8.verify_audit_slice(jsonb)
TO argus_s8_reader, argus_s8_ledger_writer;

COMMIT;
