BEGIN;

CREATE OR REPLACE FUNCTION s10.reject_quota_ledger_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'append-only table % cannot be updated, deleted, or truncated', TG_TABLE_NAME
        USING ERRCODE = '55000';
END;
$$;

DROP TRIGGER IF EXISTS quota_ledger_entry_append_only ON s10.quota_ledger_entry;
CREATE TRIGGER quota_ledger_entry_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON s10.quota_ledger_entry
    FOR EACH STATEMENT EXECUTE FUNCTION s10.reject_quota_ledger_mutation();

REVOKE UPDATE, DELETE, TRUNCATE ON s10.quota_ledger_entry FROM PUBLIC;

COMMIT;
