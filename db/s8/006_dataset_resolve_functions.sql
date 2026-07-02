BEGIN;

CREATE TABLE IF NOT EXISTS s8.dataset_resolve_audit (
    resolve_id bigserial PRIMARY KEY,
    dataset_id text NOT NULL,
    version text NOT NULL,
    split_id text NOT NULL,
    requester_scope text NOT NULL,
    verdict text NOT NULL CHECK (verdict IN ('ALLOWED', 'DENIED')),
    label_seal_ref text,
    created_at timestamptz NOT NULL DEFAULT now()
);

DROP TRIGGER IF EXISTS dataset_resolve_audit_append_only ON s8.dataset_resolve_audit;
CREATE TRIGGER dataset_resolve_audit_append_only
    BEFORE UPDATE OR DELETE ON s8.dataset_resolve_audit
    FOR EACH STATEMENT EXECUTE FUNCTION s8.reject_append_only_mutation();

CREATE OR REPLACE FUNCTION s8.assert_dataset_splits_valid(p_splits jsonb)
RETURNS void
LANGUAGE plpgsql
IMMUTABLE
SECURITY DEFINER
SET search_path = s8, pg_temp
AS $$
DECLARE
    split jsonb;
    split_id text;
    split_role text;
    access_scope text;
    row_count_text text;
    seen_split_ids text[] := ARRAY[]::text[];
BEGIN
    IF jsonb_typeof(p_splits) <> 'array' OR jsonb_array_length(p_splits) = 0 THEN
        RAISE EXCEPTION 'dataset splits must be a non-empty array'
            USING ERRCODE = '23514';
    END IF;

    FOR split IN
        SELECT value
        FROM jsonb_array_elements(p_splits) AS item(value)
    LOOP
        split_id := split->>'split_id';
        split_role := split->>'role';
        access_scope := split->>'access_scope';
        row_count_text := split->>'row_count';

        IF split_id IS NULL OR split_id = '' THEN
            RAISE EXCEPTION 'dataset split_id is required'
                USING ERRCODE = '23514';
        END IF;

        IF split_id = ANY(seen_split_ids) THEN
            RAISE EXCEPTION 'duplicate dataset split_id %', split_id
                USING ERRCODE = '23505';
        END IF;
        seen_split_ids := seen_split_ids || split_id;

        IF split_role NOT IN ('train', 'val', 'test', 'blind', 'null_control', 'injection') THEN
            RAISE EXCEPTION 'unsupported dataset split role %', split_role
                USING ERRCODE = '23514';
        END IF;

        IF access_scope NOT IN ('agent-readable', 'verifier-only') THEN
            RAISE EXCEPTION 'unsupported dataset access_scope %', access_scope
                USING ERRCODE = '23514';
        END IF;

        IF split_role IN ('blind', 'null_control', 'injection') AND access_scope <> 'verifier-only' THEN
            RAISE EXCEPTION '% split must use verifier-only access_scope', split_role
                USING ERRCODE = '23514';
        END IF;

        IF access_scope = 'verifier-only'
           AND (split->>'label_seal_ref' IS NULL OR split->>'label_seal_ref' = '') THEN
            RAISE EXCEPTION '% split requires label_seal_ref', split_role
                USING ERRCODE = '23514';
        END IF;

        IF split->>'content_hash' IS NULL OR split->>'content_hash' = '' THEN
            RAISE EXCEPTION 'dataset split content_hash is required'
                USING ERRCODE = '23514';
        END IF;

        IF split->>'schema_ref' IS NULL OR split->>'schema_ref' = '' THEN
            RAISE EXCEPTION 'dataset split schema_ref is required'
                USING ERRCODE = '23514';
        END IF;

        IF row_count_text IS NULL OR row_count_text !~ '^[0-9]+$' THEN
            RAISE EXCEPTION 'dataset split row_count must be a non-negative integer'
                USING ERRCODE = '23514';
        END IF;
    END LOOP;
END;
$$;

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
    is_verifier boolean;
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

    is_verifier := requester_scope IN ('verifier', 's8:verifier')
        OR requester_scope LIKE 'verifier:%'
        OR requester_scope LIKE '%,verifier,%'
        OR requester_scope LIKE 'verifier,%'
        OR requester_scope LIKE '%,verifier';

    IF split->>'access_scope' = 'verifier-only' THEN
        IF split->>'label_seal_ref' IS NULL OR split->>'label_seal_ref' = '' THEN
            RAISE EXCEPTION '% split requires label_seal_ref', split->>'role'
                USING ERRCODE = '23514';
        END IF;
        IF NOT is_verifier THEN
            RAISE EXCEPTION 'SCOPE_DENIED: verifier-only split %/% requires verifier scope', dataset.dataset_id, p_split_id
                USING ERRCODE = '42501';
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
        'audit_event_id', audit_id
    );
END;
$$;

REVOKE ALL ON s8.dataset_resolve_audit FROM PUBLIC;
GRANT SELECT ON s8.dataset_resolve_audit TO argus_s8_reader, argus_s8_ledger_writer;

REVOKE ALL ON FUNCTION s8.assert_dataset_splits_valid(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION s8.assert_dataset_splits_valid(jsonb)
TO argus_s8_ledger_writer;

REVOKE ALL ON FUNCTION s8.resolve_split(text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION s8.resolve_split(text, text, text, text)
TO argus_s8_reader, argus_s8_ledger_writer;

COMMIT;
