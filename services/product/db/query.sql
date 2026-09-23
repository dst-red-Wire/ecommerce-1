-- name: CreateProduct :one
INSERT INTO products (
    id, name, description, brand, manufacturer_part_number,
    status, attributes, created_at, updated_at, version
) VALUES (
    sqlc.arg(id), sqlc.arg(name), sqlc.arg(description), sqlc.arg(brand),
    sqlc.arg(manufacturer_part_number), sqlc.arg(status), sqlc.arg(attributes),
    sqlc.arg(created_at), sqlc.arg(updated_at), sqlc.arg(version)
)
RETURNING *;

-- name: GetProduct :one
SELECT * FROM products WHERE id = sqlc.arg(id);

-- name: UpdateProduct :one
UPDATE products
SET name = sqlc.arg(name),
    description = sqlc.arg(description),
    brand = sqlc.arg(brand),
    manufacturer_part_number = sqlc.arg(manufacturer_part_number),
    status = sqlc.arg(status),
    attributes = sqlc.arg(attributes),
    updated_at = sqlc.arg(updated_at),
    version = sqlc.arg(version)
WHERE id = sqlc.arg(id)
  AND version = sqlc.arg(expected_version)
RETURNING *;

-- name: ListProducts :many
SELECT *
FROM products
ORDER BY id
LIMIT sqlc.arg(limit_count)::integer
OFFSET sqlc.arg(offset_count)::integer;

-- name: ListProductsByStatus :many
SELECT *
FROM products
WHERE status = sqlc.arg(status)
ORDER BY id
LIMIT sqlc.arg(limit_count)::integer
OFFSET sqlc.arg(offset_count)::integer;

-- name: CreateSKU :one
INSERT INTO skus (
    id, product_id, code, gtin, status, option_values, attributes,
    created_at, updated_at, version
) VALUES (
    sqlc.arg(id), sqlc.arg(product_id), sqlc.arg(code), sqlc.arg(gtin),
    sqlc.arg(status), sqlc.arg(option_values), sqlc.arg(attributes),
    sqlc.arg(created_at), sqlc.arg(updated_at), sqlc.arg(version)
)
RETURNING *;

-- name: GetSKU :one
SELECT *
FROM skus
WHERE product_id = sqlc.arg(product_id)
  AND id = sqlc.arg(id);

-- name: UpdateSKU :one
UPDATE skus
SET code = sqlc.arg(code),
    gtin = sqlc.arg(gtin),
    status = sqlc.arg(status),
    option_values = sqlc.arg(option_values),
    attributes = sqlc.arg(attributes),
    updated_at = sqlc.arg(updated_at),
    version = sqlc.arg(version)
WHERE product_id = sqlc.arg(product_id)
  AND id = sqlc.arg(id)
  AND version = sqlc.arg(expected_version)
RETURNING *;

-- name: ListSKUs :many
SELECT *
FROM skus
WHERE product_id = sqlc.arg(product_id)
ORDER BY id
LIMIT sqlc.arg(limit_count)::integer
OFFSET sqlc.arg(offset_count)::integer;

-- name: GetCommand :one
SELECT journal_key, fingerprint, result_kind, result_payload, created_at
FROM command_journal
WHERE journal_key = sqlc.arg(journal_key);

-- name: CheckReadiness :one
SELECT (
    to_regclass('public.products') IS NOT NULL
    AND to_regclass('public.skus') IS NOT NULL
    AND to_regclass('public.command_journal') IS NOT NULL
    AND to_regclass('public.outbox_events') IS NOT NULL
    AND to_regclass('public.outbox_dead_letters') IS NOT NULL
)::boolean AS ready;

-- name: SaveCommand :exec
INSERT INTO command_journal (journal_key, fingerprint, result_kind, result_payload)
VALUES (
    sqlc.arg(journal_key),
    sqlc.arg(fingerprint),
    sqlc.arg(result_kind),
    sqlc.arg(result_payload)
);

-- name: InsertOutboxEvent :exec
INSERT INTO outbox_events (
    event_id, event_type, schema_version, occurred_at_utc, producer,
    aggregate_type, aggregate_id, aggregate_version,
    correlation_id, causation_id, home_site, payload
) VALUES (
    sqlc.arg(event_id), sqlc.arg(event_type), sqlc.arg(schema_version),
    sqlc.arg(occurred_at_utc), sqlc.arg(producer), sqlc.arg(aggregate_type),
    sqlc.arg(aggregate_id), sqlc.arg(aggregate_version), sqlc.arg(correlation_id),
    sqlc.arg(causation_id), sqlc.arg(home_site), sqlc.arg(payload)
);

-- name: ClaimOutboxEvents :many
WITH candidates AS (
    SELECT candidate.event_id
    FROM outbox_events AS candidate
    WHERE candidate.published_at IS NULL
      AND candidate.available_at <= sqlc.arg(p_available_before)
      AND candidate.attempt_count <= sqlc.arg(p_max_attempts)
      AND NOT EXISTS (
          SELECT 1
          FROM outbox_events AS predecessor
          WHERE predecessor.aggregate_type = candidate.aggregate_type
            AND predecessor.aggregate_id = candidate.aggregate_id
            AND predecessor.published_at IS NULL
            AND predecessor.aggregate_version < candidate.aggregate_version
      )
    ORDER BY candidate.occurred_at_utc, candidate.event_id
    FOR UPDATE SKIP LOCKED
    LIMIT sqlc.arg(p_limit_count)
)
UPDATE outbox_events AS event
SET attempt_count = event.attempt_count + 1,
    available_at = sqlc.arg(p_lease_until)
FROM candidates
WHERE event.event_id = candidates.event_id
RETURNING event.event_id, event.event_type, event.schema_version, event.aggregate_id,
          event.payload, event.attempt_count;

-- name: MarkOutboxPublished :exec
UPDATE outbox_events
SET published_at = sqlc.arg(p_published_at), last_error = ''
WHERE event_id = sqlc.arg(p_event_id) AND published_at IS NULL;

-- name: RescheduleOutboxEvent :exec
UPDATE outbox_events
SET available_at = sqlc.arg(p_available_at), last_error = sqlc.arg(p_last_error)
WHERE event_id = sqlc.arg(p_event_id) AND published_at IS NULL;

-- name: MoveOutboxEventToDeadLetter :exec
WITH moved AS (
    DELETE FROM outbox_events AS event
    WHERE event.event_id = sqlc.arg(p_event_id) AND event.published_at IS NULL
    RETURNING event.event_id, event.event_type, event.schema_version, event.occurred_at_utc, event.producer,
              event.aggregate_type, event.aggregate_id, event.aggregate_version,
              event.correlation_id, event.causation_id,
              event.home_site, event.payload, event.attempt_count
)
INSERT INTO outbox_dead_letters (
    event_id, event_type, schema_version, occurred_at_utc, producer,
    aggregate_type, aggregate_id, aggregate_version, correlation_id, causation_id,
    home_site, payload, attempt_count, last_error
)
SELECT event_id, event_type, schema_version, occurred_at_utc, producer,
       aggregate_type, aggregate_id, aggregate_version, correlation_id, causation_id,
       home_site, payload, attempt_count, sqlc.arg(p_last_error)
FROM moved;
