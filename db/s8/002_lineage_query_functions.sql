BEGIN;

CREATE OR REPLACE FUNCTION s8.query_lineage_closure(
    p_artifact_id text,
    p_direction text DEFAULT 'both',
    p_max_depth integer DEFAULT NULL
)
RETURNS TABLE (
    artifact_id text,
    direction text,
    depth integer,
    kind text,
    claim_tier text,
    validation_report_ref text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = s8, pg_temp
AS $$
BEGIN
    IF COALESCE(p_direction, '') NOT IN ('ancestors', 'descendants', 'both') THEN
        RAISE EXCEPTION 'unsupported lineage direction %', p_direction
            USING ERRCODE = '22023';
    END IF;

    IF p_max_depth IS NOT NULL AND p_max_depth < 0 THEN
        RAISE EXCEPTION 'lineage max depth must be non-negative'
            USING ERRCODE = '22023';
    END IF;

    RETURN QUERY
    SELECT
        record.artifact_id,
        'self'::text,
        0::integer,
        record.kind,
        record.claim_tier,
        record.validation_report_ref
    FROM s8.artifact_record AS record
    WHERE record.artifact_id = p_artifact_id;

    IF p_direction IN ('ancestors', 'both') THEN
        RETURN QUERY
        SELECT
            record.artifact_id,
            'ancestor'::text,
            closure.depth,
            record.kind,
            record.claim_tier,
            record.validation_report_ref
        FROM s8.lineage_closure AS closure
        JOIN s8.artifact_record AS record
          ON record.artifact_id = closure.ancestor_id
        WHERE closure.descendant_id = p_artifact_id
          AND closure.ancestor_id <> p_artifact_id
          AND (p_max_depth IS NULL OR closure.depth <= p_max_depth);
    END IF;

    IF p_direction IN ('descendants', 'both') THEN
        RETURN QUERY
        SELECT
            record.artifact_id,
            'descendant'::text,
            closure.depth,
            record.kind,
            record.claim_tier,
            record.validation_report_ref
        FROM s8.lineage_closure AS closure
        JOIN s8.artifact_record AS record
          ON record.artifact_id = closure.descendant_id
        WHERE closure.ancestor_id = p_artifact_id
          AND closure.descendant_id <> p_artifact_id
          AND (p_max_depth IS NULL OR closure.depth <= p_max_depth);
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION s8.query_lineage_recursive(
    p_artifact_id text,
    p_direction text DEFAULT 'both',
    p_edge_types text[] DEFAULT NULL,
    p_max_depth integer DEFAULT NULL
)
RETURNS TABLE (
    artifact_id text,
    direction text,
    depth integer,
    kind text,
    claim_tier text,
    validation_report_ref text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = s8, pg_temp
AS $$
BEGIN
    IF COALESCE(p_direction, '') NOT IN ('ancestors', 'descendants', 'both') THEN
        RAISE EXCEPTION 'unsupported lineage direction %', p_direction
            USING ERRCODE = '22023';
    END IF;

    IF p_max_depth IS NOT NULL AND p_max_depth < 0 THEN
        RAISE EXCEPTION 'lineage max depth must be non-negative'
            USING ERRCODE = '22023';
    END IF;

    RETURN QUERY
    SELECT
        record.artifact_id,
        'self'::text,
        0::integer,
        record.kind,
        record.claim_tier,
        record.validation_report_ref
    FROM s8.artifact_record AS record
    WHERE record.artifact_id = p_artifact_id;

    IF p_direction IN ('ancestors', 'both') THEN
        RETURN QUERY
        WITH RECURSIVE ancestor_walk(node_id, depth, path) AS (
            SELECT
                edge.src_artifact_id,
                1,
                ARRAY[p_artifact_id, edge.src_artifact_id]::text[]
            FROM s8.lineage_edge AS edge
            WHERE edge.dst_artifact_id = p_artifact_id
              AND (p_edge_types IS NULL OR edge.edge_type = ANY(p_edge_types))
              AND (p_max_depth IS NULL OR p_max_depth >= 1)
            UNION ALL
            SELECT
                edge.src_artifact_id,
                ancestor_walk.depth + 1,
                ancestor_walk.path || edge.src_artifact_id
            FROM s8.lineage_edge AS edge
            JOIN ancestor_walk
              ON ancestor_walk.node_id = edge.dst_artifact_id
            WHERE (p_edge_types IS NULL OR edge.edge_type = ANY(p_edge_types))
              AND (p_max_depth IS NULL OR ancestor_walk.depth < p_max_depth)
              AND NOT edge.src_artifact_id = ANY(ancestor_walk.path)
        )
        SELECT
            record.artifact_id,
            'ancestor'::text,
            min(ancestor_walk.depth)::integer,
            record.kind,
            record.claim_tier,
            record.validation_report_ref
        FROM ancestor_walk
        JOIN s8.artifact_record AS record
          ON record.artifact_id = ancestor_walk.node_id
        GROUP BY record.artifact_id, record.kind, record.claim_tier, record.validation_report_ref;
    END IF;

    IF p_direction IN ('descendants', 'both') THEN
        RETURN QUERY
        WITH RECURSIVE descendant_walk(node_id, depth, path) AS (
            SELECT
                edge.dst_artifact_id,
                1,
                ARRAY[p_artifact_id, edge.dst_artifact_id]::text[]
            FROM s8.lineage_edge AS edge
            WHERE edge.src_artifact_id = p_artifact_id
              AND (p_edge_types IS NULL OR edge.edge_type = ANY(p_edge_types))
              AND (p_max_depth IS NULL OR p_max_depth >= 1)
            UNION ALL
            SELECT
                edge.dst_artifact_id,
                descendant_walk.depth + 1,
                descendant_walk.path || edge.dst_artifact_id
            FROM s8.lineage_edge AS edge
            JOIN descendant_walk
              ON descendant_walk.node_id = edge.src_artifact_id
            WHERE (p_edge_types IS NULL OR edge.edge_type = ANY(p_edge_types))
              AND (p_max_depth IS NULL OR descendant_walk.depth < p_max_depth)
              AND NOT edge.dst_artifact_id = ANY(descendant_walk.path)
        )
        SELECT
            record.artifact_id,
            'descendant'::text,
            min(descendant_walk.depth)::integer,
            record.kind,
            record.claim_tier,
            record.validation_report_ref
        FROM descendant_walk
        JOIN s8.artifact_record AS record
          ON record.artifact_id = descendant_walk.node_id
        GROUP BY record.artifact_id, record.kind, record.claim_tier, record.validation_report_ref;
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION s8.query_impact_set(
    p_seed_refs text[],
    p_edge_types text[] DEFAULT ARRAY['input', 'derived_from']::text[]
)
RETURNS TABLE (
    artifact_id text,
    depth integer,
    kind text,
    claim_tier text,
    validation_report_ref text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = s8, pg_temp
AS $$
DECLARE
    normalized_seed_refs text[] := COALESCE(p_seed_refs, ARRAY[]::text[]);
BEGIN
    RETURN QUERY
    WITH RECURSIVE impact_walk(node_id, depth, path) AS (
        SELECT
            edge.dst_artifact_id,
            1,
            ARRAY[edge.src_artifact_id, edge.dst_artifact_id]::text[]
        FROM s8.lineage_edge AS edge
        WHERE edge.src_artifact_id = ANY(normalized_seed_refs)
          AND (p_edge_types IS NULL OR edge.edge_type = ANY(p_edge_types))
        UNION ALL
        SELECT
            edge.dst_artifact_id,
            impact_walk.depth + 1,
            impact_walk.path || edge.dst_artifact_id
        FROM s8.lineage_edge AS edge
        JOIN impact_walk
          ON impact_walk.node_id = edge.src_artifact_id
        WHERE (p_edge_types IS NULL OR edge.edge_type = ANY(p_edge_types))
          AND NOT edge.dst_artifact_id = ANY(impact_walk.path)
    )
    SELECT
        record.artifact_id,
        min(impact_walk.depth)::integer,
        record.kind,
        record.claim_tier,
        record.validation_report_ref
    FROM impact_walk
    JOIN s8.artifact_record AS record
      ON record.artifact_id = impact_walk.node_id
    WHERE NOT record.artifact_id = ANY(normalized_seed_refs)
    GROUP BY record.artifact_id, record.kind, record.claim_tier, record.validation_report_ref;
END;
$$;

CREATE OR REPLACE FUNCTION s8.verify_lineage_closure(p_artifact_id text)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = s8, pg_temp
AS $$
DECLARE
    diff_count integer;
BEGIN
    WITH closure_rows AS (
        SELECT artifact_id, direction, depth
        FROM s8.query_lineage_closure(p_artifact_id, 'both', NULL)
        WHERE direction <> 'self'
    ),
    recursive_rows AS (
        SELECT artifact_id, direction, depth
        FROM s8.query_lineage_recursive(p_artifact_id, 'both', NULL, NULL)
        WHERE direction <> 'self'
    ),
    diff_rows AS (
        (SELECT * FROM closure_rows EXCEPT SELECT * FROM recursive_rows)
        UNION ALL
        (SELECT * FROM recursive_rows EXCEPT SELECT * FROM closure_rows)
    )
    SELECT count(*)::integer
    INTO diff_count
    FROM diff_rows;

    RETURN diff_count = 0;
END;
$$;

REVOKE ALL ON FUNCTION s8.query_lineage_closure(text, text, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION s8.query_lineage_closure(text, text, integer)
TO argus_s8_reader, argus_s8_ledger_writer;

REVOKE ALL ON FUNCTION s8.query_lineage_recursive(text, text, text[], integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION s8.query_lineage_recursive(text, text, text[], integer)
TO argus_s8_reader, argus_s8_ledger_writer;

REVOKE ALL ON FUNCTION s8.query_impact_set(text[], text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION s8.query_impact_set(text[], text[])
TO argus_s8_reader, argus_s8_ledger_writer;

REVOKE ALL ON FUNCTION s8.verify_lineage_closure(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION s8.verify_lineage_closure(text)
TO argus_s8_reader, argus_s8_ledger_writer;

COMMIT;
