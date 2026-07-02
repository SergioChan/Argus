BEGIN;

CREATE OR REPLACE FUNCTION s8.reject_append_only_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'append-only table % cannot be updated, deleted, or truncated', TG_TABLE_NAME
        USING ERRCODE = '55000';
END;
$$;

DROP TRIGGER IF EXISTS artifact_record_append_only ON s8.artifact_record;
CREATE TRIGGER artifact_record_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON s8.artifact_record
    FOR EACH STATEMENT EXECUTE FUNCTION s8.reject_append_only_mutation();

DROP TRIGGER IF EXISTS lineage_edge_append_only ON s8.lineage_edge;
CREATE TRIGGER lineage_edge_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON s8.lineage_edge
    FOR EACH STATEMENT EXECUTE FUNCTION s8.reject_append_only_mutation();

DROP TRIGGER IF EXISTS lineage_closure_append_only ON s8.lineage_closure;
CREATE TRIGGER lineage_closure_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON s8.lineage_closure
    FOR EACH STATEMENT EXECUTE FUNCTION s8.reject_append_only_mutation();

DROP TRIGGER IF EXISTS external_source_append_only ON s8.external_source;
CREATE TRIGGER external_source_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON s8.external_source
    FOR EACH STATEMENT EXECUTE FUNCTION s8.reject_append_only_mutation();

DROP TRIGGER IF EXISTS merkle_checkpoint_append_only ON s8.merkle_checkpoint;
CREATE TRIGGER merkle_checkpoint_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON s8.merkle_checkpoint
    FOR EACH STATEMENT EXECUTE FUNCTION s8.reject_append_only_mutation();

DROP TRIGGER IF EXISTS ledger_leaf_append_only ON s8.ledger_leaf;
CREATE TRIGGER ledger_leaf_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON s8.ledger_leaf
    FOR EACH STATEMENT EXECUTE FUNCTION s8.reject_append_only_mutation();

DROP TRIGGER IF EXISTS reproducibility_check_append_only ON s8.reproducibility_check;
CREATE TRIGGER reproducibility_check_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON s8.reproducibility_check
    FOR EACH STATEMENT EXECUTE FUNCTION s8.reject_append_only_mutation();

DROP TRIGGER IF EXISTS dataset_registry_append_only ON s8.dataset_registry;
CREATE TRIGGER dataset_registry_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON s8.dataset_registry
    FOR EACH STATEMENT EXECUTE FUNCTION s8.reject_append_only_mutation();

DROP TRIGGER IF EXISTS dataset_resolve_audit_append_only ON s8.dataset_resolve_audit;
CREATE TRIGGER dataset_resolve_audit_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON s8.dataset_resolve_audit
    FOR EACH STATEMENT EXECUTE FUNCTION s8.reject_append_only_mutation();

REVOKE TRUNCATE ON
    s8.artifact_record,
    s8.lineage_edge,
    s8.lineage_closure,
    s8.external_source,
    s8.merkle_checkpoint,
    s8.ledger_leaf,
    s8.reproducibility_check,
    s8.dataset_registry,
    s8.dataset_resolve_audit
FROM PUBLIC, argus_s8_reader, argus_s8_ledger_writer;

COMMIT;
