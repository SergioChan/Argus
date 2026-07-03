BEGIN;

CREATE OR REPLACE FUNCTION s8.lineage_closure_drift(p_artifact_id text)
RETURNS TABLE (
    artifact_id text,
    direction text,
    closure_depth integer,
    recursive_depth integer,
    drift_status text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = s8, pg_temp
AS $$
BEGIN
    RETURN QUERY
    WITH closure_rows AS (
        SELECT
            row.artifact_id,
            row.direction,
            row.depth
        FROM s8.query_lineage_closure(p_artifact_id, 'both', NULL) AS row
        WHERE row.direction <> 'self'
    ),
    recursive_rows AS (
        SELECT
            row.artifact_id,
            row.direction,
            row.depth
        FROM s8.query_lineage_recursive(p_artifact_id, 'both', NULL, NULL) AS row
        WHERE row.direction <> 'self'
    )
    SELECT
        COALESCE(closure_rows.artifact_id, recursive_rows.artifact_id),
        COALESCE(closure_rows.direction, recursive_rows.direction),
        closure_rows.depth,
        recursive_rows.depth,
        CASE
            WHEN closure_rows.artifact_id IS NULL THEN 'missing_from_closure'
            WHEN recursive_rows.artifact_id IS NULL THEN 'stale_in_closure'
            ELSE 'depth_mismatch'
        END
    FROM closure_rows
    FULL OUTER JOIN recursive_rows
      ON recursive_rows.artifact_id = closure_rows.artifact_id
     AND recursive_rows.direction = closure_rows.direction
    WHERE closure_rows.artifact_id IS NULL
       OR recursive_rows.artifact_id IS NULL
       OR closure_rows.depth <> recursive_rows.depth
    ORDER BY
        COALESCE(closure_rows.direction, recursive_rows.direction),
        COALESCE(closure_rows.artifact_id, recursive_rows.artifact_id);
END;
$$;

CREATE OR REPLACE FUNCTION s8.rebuild_lineage_closure()
RETURNS integer
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = s8, pg_temp
AS $$
DECLARE
    inserted_count integer;
BEGIN
    LOCK TABLE s8.lineage_edge, s8.lineage_closure IN SHARE ROW EXCLUSIVE MODE;

    ALTER TABLE s8.lineage_closure DISABLE TRIGGER lineage_closure_append_only;
    DELETE FROM s8.lineage_closure;

    WITH RECURSIVE lineage_walk(ancestor_id, descendant_id, depth, path) AS (
        SELECT
            edge.src_artifact_id,
            edge.dst_artifact_id,
            1,
            ARRAY[edge.src_artifact_id, edge.dst_artifact_id]::text[]
        FROM s8.lineage_edge AS edge
        UNION ALL
        SELECT
            lineage_walk.ancestor_id,
            edge.dst_artifact_id,
            lineage_walk.depth + 1,
            lineage_walk.path || edge.dst_artifact_id
        FROM lineage_walk
        JOIN s8.lineage_edge AS edge
          ON edge.src_artifact_id = lineage_walk.descendant_id
        WHERE NOT edge.dst_artifact_id = ANY(lineage_walk.path)
    )
    INSERT INTO s8.lineage_closure (ancestor_id, descendant_id, depth)
    SELECT
        lineage_walk.ancestor_id,
        lineage_walk.descendant_id,
        min(lineage_walk.depth)::integer
    FROM lineage_walk
    GROUP BY lineage_walk.ancestor_id, lineage_walk.descendant_id
    ON CONFLICT (ancestor_id, descendant_id) DO UPDATE
        SET depth = EXCLUDED.depth;

    SELECT count(*)::integer
    INTO inserted_count
    FROM s8.lineage_closure;

    ALTER TABLE s8.lineage_closure ENABLE TRIGGER lineage_closure_append_only;
    RETURN inserted_count;
EXCEPTION WHEN OTHERS THEN
    BEGIN
        ALTER TABLE s8.lineage_closure ENABLE TRIGGER lineage_closure_append_only;
    EXCEPTION WHEN OTHERS THEN
        NULL;
    END;
    RAISE;
END;
$$;

REVOKE ALL ON FUNCTION s8.lineage_closure_drift(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION s8.lineage_closure_drift(text)
TO argus_s8_reader, argus_s8_ledger_writer;

REVOKE ALL ON FUNCTION s8.rebuild_lineage_closure() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION s8.rebuild_lineage_closure()
TO argus_s8_ledger_writer;

COMMIT;
