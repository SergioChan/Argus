BEGIN;

CREATE OR REPLACE FUNCTION s8.resolve_split(
    p_dataset_id text,
    p_version text,
    p_split_id text,
    p_requester_scope text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = s8, pg_temp
AS $$
DECLARE
    dataset s8.dataset_registry%ROWTYPE;
    split jsonb;
    label_blob_ref text;
    audit_id bigint;
    requester_scope text := COALESCE(p_requester_scope, '');
    requester_capabilities text[];
    is_verifier boolean;
    denied_message text;
BEGIN
    IF COALESCE(p_dataset_id, '') = '' THEN
        RAISE EXCEPTION 'dataset_id is required'
            USING ERRCODE = '23514';
    END IF;

    IF COALESCE(p_split_id, '') = '' THEN
        RAISE EXCEPTION 'split_id is required'
            USING ERRCODE = '23514';
    END IF;

    IF p_version IS NULL THEN
        SELECT *
        INTO dataset
        FROM s8.dataset_registry
        WHERE dataset_id = p_dataset_id
        ORDER BY s8.dataset_version_sort_key(version) DESC, version DESC
        LIMIT 1;
    ELSE
        SELECT *
        INTO dataset
        FROM s8.dataset_registry
        WHERE dataset_id = p_dataset_id
          AND version = p_version;
    END IF;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'dataset % version % not found', p_dataset_id, COALESCE(p_version, '<latest>')
            USING ERRCODE = '23503';
    END IF;

    SELECT value
    INTO split
    FROM jsonb_array_elements(dataset.splits) AS item(value)
    WHERE value->>'split_id' = p_split_id
    LIMIT 1;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'dataset split % not found for % version %', p_split_id, dataset.dataset_id, dataset.version
            USING ERRCODE = '23503';
    END IF;

    SELECT COALESCE(array_agg(trim(value)), ARRAY[]::text[])
    INTO requester_capabilities
    FROM unnest(string_to_array(requester_scope, ',')) AS item(value)
    WHERE trim(value) <> '';
    is_verifier := 's8.verifier-labels.read' = ANY(requester_capabilities);

    IF split->>'access_scope' = 'verifier-only' THEN
        IF split->>'label_seal_ref' IS NULL OR split->>'label_seal_ref' = '' THEN
            RAISE EXCEPTION '% split requires label_seal_ref', split->>'role'
                USING ERRCODE = '23514';
        END IF;
        IF NOT is_verifier THEN
            INSERT INTO s8.dataset_resolve_audit (
                dataset_id,
                version,
                split_id,
                requester_scope,
                verdict,
                label_seal_ref
            ) VALUES (
                dataset.dataset_id,
                dataset.version,
                p_split_id,
                requester_scope,
                'DENIED',
                NULL
            )
            RETURNING resolve_id INTO audit_id;

            denied_message := format(
                'SCOPE_DENIED: verifier-only split %s/%s requires s8.verifier-labels.read capability',
                dataset.dataset_id,
                p_split_id
            );
            RETURN jsonb_build_object(
                'dataset_id', dataset.dataset_id,
                'version', dataset.version,
                'split_id', p_split_id,
                'role', split->>'role',
                'verdict', 'DENIED',
                'category', 'SCOPE_DENIED',
                'message', denied_message,
                'audit_event_id', audit_id
            );
        END IF;
        label_blob_ref := split->>'label_seal_ref';
    END IF;

    INSERT INTO s8.dataset_resolve_audit (
        dataset_id,
        version,
        split_id,
        requester_scope,
        verdict,
        label_seal_ref
    ) VALUES (
        dataset.dataset_id,
        dataset.version,
        p_split_id,
        requester_scope,
        'ALLOWED',
        label_blob_ref
    )
    RETURNING resolve_id INTO audit_id;

    RETURN jsonb_build_object(
        'dataset_id', dataset.dataset_id,
        'version', dataset.version,
        'split_id', p_split_id,
        'role', split->>'role',
        'feature_blob_ref', split->>'content_hash',
        'label_blob_ref', label_blob_ref,
        'audit_event_id', audit_id,
        'verdict', 'ALLOWED'
    );
END;
$$;

REVOKE ALL ON FUNCTION s8.resolve_split(text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION s8.resolve_split(text, text, text, text)
TO argus_s8_reader, argus_s8_ledger_writer;

COMMIT;
