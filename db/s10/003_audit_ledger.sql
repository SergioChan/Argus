BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 's10_audit_writer') THEN
        CREATE ROLE s10_audit_writer NOLOGIN;
    END IF;
END;
$$;

CREATE TABLE IF NOT EXISTS s10.audit_event (
    sequence bigint PRIMARY KEY CHECK (sequence >= 1),
    event_type text NOT NULL CHECK (length(event_type) > 0),
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    previous_hash text NOT NULL CHECK (previous_hash ~ '^blake3:[0-9a-f]{64}$'),
    event_hash text NOT NULL UNIQUE CHECK (event_hash ~ '^blake3:[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS s10.audit_anchor (
    sequence bigint PRIMARY KEY REFERENCES s10.audit_event(sequence),
    previous_root text NOT NULL CHECK (previous_root ~ '^blake3:[0-9a-f]{64}$'),
    root text NOT NULL UNIQUE CHECK (root ~ '^blake3:[0-9a-f]{64}$'),
    artifact_ref text NOT NULL UNIQUE CHECK (length(artifact_ref) > 0),
    content_hash text NOT NULL CHECK (content_hash ~ '^blake3:[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_event_job_sequence_idx
    ON s10.audit_event ((payload ->> 'job_id'), sequence);
CREATE INDEX IF NOT EXISTS audit_event_type_sequence_idx
    ON s10.audit_event (event_type, sequence);
CREATE INDEX IF NOT EXISTS audit_event_severity_sequence_idx
    ON s10.audit_event ((payload ->> 'severity'), sequence);
CREATE INDEX IF NOT EXISTS audit_event_created_at_idx
    ON s10.audit_event (created_at, sequence);

CREATE OR REPLACE FUNCTION s10.reject_audit_ledger_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'append-only table % cannot be updated, deleted, or truncated', TG_TABLE_NAME
        USING ERRCODE = '55000';
END;
$$;

DROP TRIGGER IF EXISTS audit_event_append_only ON s10.audit_event;
CREATE TRIGGER audit_event_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON s10.audit_event
    FOR EACH STATEMENT EXECUTE FUNCTION s10.reject_audit_ledger_mutation();

DROP TRIGGER IF EXISTS audit_anchor_append_only ON s10.audit_anchor;
CREATE TRIGGER audit_anchor_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON s10.audit_anchor
    FOR EACH STATEMENT EXECUTE FUNCTION s10.reject_audit_ledger_mutation();

CREATE OR REPLACE FUNCTION s10.append_audit_event(
    p_sequence bigint,
    p_event_type text,
    p_payload jsonb,
    p_previous_hash text,
    p_event_hash text,
    p_previous_root text,
    p_root text,
    p_artifact_ref text,
    p_content_hash text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, s10
AS $$
DECLARE
    v_last_sequence bigint;
    v_last_hash text;
    v_last_root text;
    v_zero_hash constant text := 'blake3:' || repeat('0', 64);
BEGIN
    PERFORM pg_advisory_xact_lock(5038301002);

    SELECT e.sequence, e.event_hash, a.root
    INTO v_last_sequence, v_last_hash, v_last_root
    FROM s10.audit_event AS e
    JOIN s10.audit_anchor AS a USING (sequence)
    ORDER BY e.sequence DESC
    LIMIT 1;

    IF p_sequence <> COALESCE(v_last_sequence, 0) + 1 THEN
        RAISE EXCEPTION 'audit sequence is not the next ledger position';
    END IF;
    IF p_previous_hash <> COALESCE(v_last_hash, v_zero_hash) THEN
        RAISE EXCEPTION 'audit previous hash does not match the ledger tip';
    END IF;
    IF p_previous_root <> COALESCE(v_last_root, v_zero_hash) THEN
        RAISE EXCEPTION 'audit previous root does not match the ledger tip';
    END IF;

    INSERT INTO s10.audit_event (sequence, event_type, payload, previous_hash, event_hash)
    VALUES (p_sequence, p_event_type, p_payload, p_previous_hash, p_event_hash);

    INSERT INTO s10.audit_anchor (
        sequence,
        previous_root,
        root,
        artifact_ref,
        content_hash
    )
    VALUES (
        p_sequence,
        p_previous_root,
        p_root,
        p_artifact_ref,
        p_content_hash
    );
END;
$$;

REVOKE ALL ON s10.audit_event FROM PUBLIC;
REVOKE ALL ON s10.audit_anchor FROM PUBLIC;
REVOKE ALL ON FUNCTION s10.append_audit_event(bigint, text, jsonb, text, text, text, text, text, text)
    FROM PUBLIC;
GRANT USAGE ON SCHEMA s10 TO s10_audit_writer;
GRANT SELECT ON s10.audit_event, s10.audit_anchor TO s10_audit_writer;
GRANT EXECUTE ON FUNCTION s10.append_audit_event(bigint, text, jsonb, text, text, text, text, text, text)
    TO s10_audit_writer;

COMMIT;
