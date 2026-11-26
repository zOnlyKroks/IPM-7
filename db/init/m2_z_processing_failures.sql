-- M2 v1.3: persistent failure/backoff table (safe for existing M2 v1.2 DB).
-- Run once with psql; no DROP and no changes to M1 tables.
BEGIN;
CREATE SCHEMA IF NOT EXISTS m2;
CREATE TABLE IF NOT EXISTS m2.processing_failures (
    raw_item_id bigint PRIMARY KEY REFERENCES public.raw_items(id),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error text NOT NULL DEFAULT '',
    last_failed_at timestamptz NOT NULL DEFAULT now(),
    next_retry_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS processing_failures_next_retry_idx
    ON m2.processing_failures (next_retry_at);
COMMIT;
