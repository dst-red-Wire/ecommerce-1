-- Product domain authoritative PostgreSQL schema.
-- Forward-only migration: rollback of this initial schema is database recreation/restore,
-- not an in-place destructive DOWN migration.

CREATE TABLE products (
    id uuid PRIMARY KEY,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 10000),
    brand text NOT NULL DEFAULT '' CHECK (char_length(brand) <= 200),
    manufacturer_part_number text NOT NULL DEFAULT '' CHECK (char_length(manufacturer_part_number) <= 200),
    status text NOT NULL CHECK (status IN ('draft', 'active', 'archived')),
    attributes jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(attributes) = 'object'),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    version bigint NOT NULL CHECK (version >= 1)
);

CREATE INDEX products_status_id_idx ON products (status, id);

CREATE TABLE skus (
    id uuid PRIMARY KEY,
    product_id uuid NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
    code text NOT NULL UNIQUE CHECK (char_length(code) BETWEEN 1 AND 100),
    gtin text NOT NULL DEFAULT '' CHECK (gtin = '' OR gtin ~ '^[0-9]{8,14}$'),
    status text NOT NULL CHECK (status IN ('active', 'inactive', 'archived')),
    option_values jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(option_values) = 'object'),
    attributes jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(attributes) = 'object'),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    version bigint NOT NULL CHECK (version >= 1)
);

CREATE INDEX skus_product_id_id_idx ON skus (product_id, id);

CREATE TABLE command_journal (
    journal_key text PRIMARY KEY,
    fingerprint text NOT NULL CHECK (char_length(fingerprint) = 64),
    result_kind text NOT NULL CHECK (result_kind IN ('product', 'sku')),
    result_payload jsonb NOT NULL CHECK (jsonb_typeof(result_payload) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now()
);
