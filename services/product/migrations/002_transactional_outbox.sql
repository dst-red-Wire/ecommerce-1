-- Expand migration: durable Product events are committed in the same PostgreSQL
-- transaction as the aggregate mutation and idempotency command journal.
CREATE TABLE outbox_events (
    event_id uuid PRIMARY KEY,
    event_type text NOT NULL,
    schema_version integer NOT NULL CHECK (schema_version >= 1),
    occurred_at_utc timestamptz NOT NULL,
    producer text NOT NULL,
    aggregate_type text NOT NULL,
    aggregate_id uuid NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version >= 1),
    correlation_id text NOT NULL,
    causation_id text NOT NULL,
    home_site text NOT NULL,
    payload bytea NOT NULL CHECK (octet_length(payload) > 0),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    available_at timestamptz NOT NULL DEFAULT now(),
    published_at timestamptz,
    last_error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX outbox_events_aggregate_version_idx
    ON outbox_events (aggregate_type, aggregate_id, aggregate_version);

CREATE INDEX outbox_events_pending_idx
    ON outbox_events (available_at, occurred_at_utc)
    WHERE published_at IS NULL;

CREATE TABLE outbox_dead_letters (
    event_id uuid PRIMARY KEY,
    event_type text NOT NULL,
    schema_version integer NOT NULL,
    occurred_at_utc timestamptz NOT NULL,
    producer text NOT NULL,
    aggregate_type text NOT NULL,
    aggregate_id uuid NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version >= 1),
    correlation_id text NOT NULL,
    causation_id text NOT NULL,
    home_site text NOT NULL,
    payload bytea NOT NULL,
    attempt_count integer NOT NULL,
    last_error text NOT NULL,
    failed_at timestamptz NOT NULL DEFAULT now()
);
