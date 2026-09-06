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

-- name: SaveCommand :exec
INSERT INTO command_journal (journal_key, fingerprint, result_kind, result_payload)
VALUES (
    sqlc.arg(journal_key),
    sqlc.arg(fingerprint),
    sqlc.arg(result_kind),
    sqlc.arg(result_payload)
);
