CREATE SCHEMA IF NOT EXISTS s10;

CREATE TABLE IF NOT EXISTS s10.schema_migration (
    migration_id text PRIMARY KEY,
    checksum_sha256 text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS s10.quota_budget (
    budget_id text PRIMARY KEY,
    job_id text NOT NULL,
    root_request_id text NOT NULL,
    risk_class text NOT NULL,
    budget_epoch integer NOT NULL,
    caps jsonb NOT NULL,
    reserved jsonb NOT NULL DEFAULT '{}'::jsonb,
    actual jsonb NOT NULL DEFAULT '{}'::jsonb,
    halted boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS s10.quota_ledger_entry (
    sequence bigserial PRIMARY KEY,
    budget_id text NOT NULL REFERENCES s10.quota_budget(budget_id),
    entry_type text NOT NULL CHECK (entry_type IN ('register', 'reserve', 'consume', 'release', 'halt')),
    delta jsonb NOT NULL,
    reserved_after jsonb NOT NULL,
    actual_after jsonb NOT NULL,
    remaining_after jsonb NOT NULL,
    halted_after boolean NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS quota_ledger_entry_budget_seq_idx
    ON s10.quota_ledger_entry (budget_id, sequence);
