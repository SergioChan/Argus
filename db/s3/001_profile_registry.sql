BEGIN;

CREATE SCHEMA IF NOT EXISTS s3;

CREATE TABLE IF NOT EXISTS s3.schema_migration (
    migration_id text PRIMARY KEY,
    checksum_sha256 text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now(),
    applied_by text NOT NULL DEFAULT current_user
);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'argus_s3_reader') THEN
        CREATE ROLE argus_s3_reader NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'argus_s3_profile_writer') THEN
        CREATE ROLE argus_s3_profile_writer NOLOGIN;
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS s3.verifier_profile_revision (
    profile_id text NOT NULL CHECK (profile_id ~ '^[A-Za-z0-9._-]+$'),
    revision integer NOT NULL CHECK (revision >= 1),
    profile_ref text NOT NULL UNIQUE CHECK (profile_ref ~ '^c4://profile/[A-Za-z0-9._-]+/r[0-9]+$'),
    subtopic text NOT NULL CHECK (length(subtopic) > 0),
    checks text[] NOT NULL CHECK (array_length(checks, 1) > 0),
    cost_estimate jsonb NOT NULL CHECK (jsonb_typeof(cost_estimate) = 'object'),
    spec_json jsonb NOT NULL CHECK (jsonb_typeof(spec_json) = 'object'),
    spec_hash text NOT NULL UNIQUE CHECK (spec_hash LIKE 'blake3:%'),
    published_by text NOT NULL DEFAULT current_user,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (profile_id, revision),
    CHECK ((spec_json->>'profile_id') = profile_id),
    CHECK (((spec_json->>'revision')::integer) = revision),
    CHECK ((spec_json->>'profile_ref') = profile_ref),
    CHECK ((spec_json->>'subtopic') = subtopic)
);

CREATE TABLE IF NOT EXISTS s3.verifier_profile_status_event (
    event_id bigserial PRIMARY KEY,
    profile_id text NOT NULL,
    revision integer NOT NULL,
    status text NOT NULL CHECK (status IN ('active', 'deprecated', 'revoked')),
    reason text NOT NULL CHECK (length(reason) > 0),
    actor text NOT NULL CHECK (length(actor) > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (profile_id, revision)
        REFERENCES s3.verifier_profile_revision(profile_id, revision)
);

CREATE OR REPLACE FUNCTION s3.reject_append_only_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'append-only table % cannot be updated, deleted, or truncated', TG_TABLE_NAME
        USING ERRCODE = '55000';
END;
$$;

DROP TRIGGER IF EXISTS verifier_profile_revision_append_only ON s3.verifier_profile_revision;
CREATE TRIGGER verifier_profile_revision_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON s3.verifier_profile_revision
    FOR EACH STATEMENT EXECUTE FUNCTION s3.reject_append_only_mutation();

DROP TRIGGER IF EXISTS verifier_profile_status_event_append_only ON s3.verifier_profile_status_event;
CREATE TRIGGER verifier_profile_status_event_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON s3.verifier_profile_status_event
    FOR EACH STATEMENT EXECUTE FUNCTION s3.reject_append_only_mutation();

GRANT USAGE ON SCHEMA s3 TO argus_s3_reader, argus_s3_profile_writer;
GRANT SELECT ON
    s3.verifier_profile_revision,
    s3.verifier_profile_status_event
TO argus_s3_reader, argus_s3_profile_writer;
GRANT INSERT ON
    s3.verifier_profile_revision,
    s3.verifier_profile_status_event
TO argus_s3_profile_writer;
GRANT USAGE, SELECT ON SEQUENCE s3.verifier_profile_status_event_event_id_seq TO argus_s3_profile_writer;
REVOKE UPDATE, DELETE, TRUNCATE ON
    s3.verifier_profile_revision,
    s3.verifier_profile_status_event
FROM PUBLIC, argus_s3_reader, argus_s3_profile_writer;

COMMIT;
