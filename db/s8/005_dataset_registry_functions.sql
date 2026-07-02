BEGIN;

CREATE TABLE IF NOT EXISTS s8.dataset_registry (
    dataset_id text NOT NULL,
    version text NOT NULL,
    dataset_artifact_id text NOT NULL UNIQUE REFERENCES s8.artifact_record(artifact_id),
    splits jsonb NOT NULL,
    contamination_index_version text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (dataset_id, version)
);

CREATE OR REPLACE FUNCTION s8.dataset_version_sort_key(p_version text)
RETURNS text
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT CASE
        WHEN p_version ~ '^[0-9]+(\.[0-9]+)*$' THEN
            '0:' || (
                SELECT string_agg(lpad(part, 12, '0'), '.' ORDER BY ordinality)
                FROM unnest(string_to_array(p_version, '.')) WITH ORDINALITY AS parts(part, ordinality)
            )
        ELSE '1:' || p_version
    END;
$$;

DROP TRIGGER IF EXISTS dataset_registry_append_only ON s8.dataset_registry;
CREATE TRIGGER dataset_registry_append_only
    BEFORE UPDATE OR DELETE ON s8.dataset_registry
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

CREATE OR REPLACE FUNCTION s8.register_dataset(
    p_dataset_id text,
    p_version text,
    p_dataset_artifact_id text,
    p_splits jsonb,
    p_contamination_index_version text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = s8, pg_temp
AS $$
DECLARE
    existing_dataset s8.dataset_registry%ROWTYPE;
    artifact_kind text;
BEGIN
    IF COALESCE(p_dataset_id, '') = '' THEN
        RAISE EXCEPTION 'dataset_id is required'
            USING ERRCODE = '23514';
    END IF;

    IF COALESCE(p_version, '') = '' THEN
        RAISE EXCEPTION 'dataset version is required'
            USING ERRCODE = '23514';
    END IF;

    IF COALESCE(p_contamination_index_version, '') = '' THEN
        RAISE EXCEPTION 'contamination_index_version is required'
            USING ERRCODE = '23514';
    END IF;

    PERFORM s8.assert_dataset_splits_valid(p_splits);

    SELECT kind
    INTO artifact_kind
    FROM s8.artifact_record
    WHERE artifact_id = p_dataset_artifact_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'dataset artifact % does not exist', p_dataset_artifact_id
            USING ERRCODE = '23503';
    END IF;

    IF artifact_kind <> 'dataset' THEN
        RAISE EXCEPTION 'dataset artifact % has kind %', p_dataset_artifact_id, artifact_kind
            USING ERRCODE = '23514';
    END IF;

    SELECT *
    INTO existing_dataset
    FROM s8.dataset_registry
    WHERE dataset_id = p_dataset_id
      AND version = p_version;

    IF FOUND THEN
        IF existing_dataset.dataset_artifact_id = p_dataset_artifact_id
           AND existing_dataset.splits = p_splits
           AND existing_dataset.contamination_index_version = p_contamination_index_version THEN
            RETURN FALSE;
        END IF;

        RAISE EXCEPTION 'dataset % version % already exists with different payload', p_dataset_id, p_version
            USING ERRCODE = '23505';
    END IF;

    INSERT INTO s8.dataset_registry (
        dataset_id,
        version,
        dataset_artifact_id,
        splits,
        contamination_index_version
    ) VALUES (
        p_dataset_id,
        p_version,
        p_dataset_artifact_id,
        p_splits,
        p_contamination_index_version
    );

    RETURN TRUE;
END;
$$;

CREATE OR REPLACE FUNCTION s8.get_dataset(
    p_dataset_id text,
    p_version text DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = s8, pg_temp
AS $$
DECLARE
    dataset s8.dataset_registry%ROWTYPE;
    artifact s8.artifact_record%ROWTYPE;
    masked_splits jsonb;
BEGIN
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

    SELECT *
    INTO artifact
    FROM s8.artifact_record
    WHERE artifact_id = dataset.dataset_artifact_id;

    SELECT COALESCE(
        jsonb_agg(
            CASE
                WHEN value->>'access_scope' = 'verifier-only' THEN value - 'content_hash' - 'label_seal_ref'
                ELSE value
            END
            ORDER BY ordinality
        ),
        '[]'::jsonb
    )
    INTO masked_splits
    FROM jsonb_array_elements(dataset.splits) WITH ORDINALITY AS item(value, ordinality);

    RETURN jsonb_build_object(
        'dataset_id', dataset.dataset_id,
        'version', dataset.version,
        'splits', masked_splits,
        'contamination_index_version', dataset.contamination_index_version,
        'provenance_ref', jsonb_build_object(
            'artifact_id', artifact.artifact_id,
            'content_hash', artifact.content_hash
        ),
        'created_at', dataset.created_at
    );
END;
$$;

CREATE OR REPLACE FUNCTION s8.list_dataset_versions(p_dataset_id text)
RETURNS TABLE(version text)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = s8, pg_temp
AS $$
    SELECT dataset.version
    FROM s8.dataset_registry AS dataset
    WHERE dataset.dataset_id = p_dataset_id
    ORDER BY s8.dataset_version_sort_key(dataset.version), dataset.version;
$$;

REVOKE ALL ON s8.dataset_registry FROM PUBLIC;
REVOKE ALL ON s8.dataset_registry FROM argus_s8_reader, argus_s8_ledger_writer;

REVOKE ALL ON FUNCTION s8.dataset_version_sort_key(text) FROM PUBLIC;

REVOKE ALL ON FUNCTION s8.assert_dataset_splits_valid(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION s8.assert_dataset_splits_valid(jsonb)
TO argus_s8_ledger_writer;

REVOKE ALL ON FUNCTION s8.register_dataset(text, text, text, jsonb, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION s8.register_dataset(text, text, text, jsonb, text)
TO argus_s8_ledger_writer;

REVOKE ALL ON FUNCTION s8.get_dataset(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION s8.get_dataset(text, text)
TO argus_s8_reader, argus_s8_ledger_writer;

REVOKE ALL ON FUNCTION s8.list_dataset_versions(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION s8.list_dataset_versions(text)
TO argus_s8_reader, argus_s8_ledger_writer;

COMMIT;
