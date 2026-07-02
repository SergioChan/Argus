BEGIN;

DO $$
BEGIN
    IF to_regprocedure('s8.verify_audit_chain()') IS NOT NULL THEN
        REVOKE ALL ON FUNCTION s8.verify_audit_chain()
        FROM PUBLIC, argus_s8_reader, argus_s8_ledger_writer;
    END IF;

    IF to_regprocedure('s8.verify_audit_slice(jsonb)') IS NOT NULL THEN
        REVOKE ALL ON FUNCTION s8.verify_audit_slice(jsonb)
        FROM PUBLIC, argus_s8_reader, argus_s8_ledger_writer;
    END IF;
END
$$;

DROP FUNCTION IF EXISTS s8.verify_audit_chain();
DROP FUNCTION IF EXISTS s8.verify_audit_slice(jsonb);

COMMIT;
