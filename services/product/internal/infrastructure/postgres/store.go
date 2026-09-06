package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/application"
	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/domain"
	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/infrastructure/postgres/sqlcgen"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool    *pgxpool.Pool
	queries *sqlcgen.Queries
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool, queries: sqlcgen.New(pool)}
}

func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

func (s *Store) CreateProduct(ctx context.Context, product domain.Product) error {
	attributes, err := json.Marshal(product.Attributes)
	if err != nil {
		return err
	}
	_, err = s.queries.CreateProduct(ctx, sqlcgen.CreateProductParams{
		ID: product.ID, Name: product.Name, Description: product.Description,
		Brand: product.Brand, ManufacturerPartNumber: product.ManufacturerPartNumber,
		Status: string(product.Status), Attributes: attributes,
		CreatedAt: pgtype.Timestamptz{Time: product.CreatedAt, Valid: true}, UpdatedAt: pgtype.Timestamptz{Time: product.UpdatedAt, Valid: true}, Version: product.Version,
	})
	return mapWriteError(err)
}

func (s *Store) GetProduct(ctx context.Context, id string) (domain.Product, error) {
	row, err := s.queries.GetProduct(ctx, id)
	if err != nil {
		return domain.Product{}, mapReadError(err)
	}
	return productFromRow(row)
}

func (s *Store) UpdateProduct(ctx context.Context, product domain.Product, expectedVersion int64) (domain.Product, error) {
	attributes, err := json.Marshal(product.Attributes)
	if err != nil {
		return domain.Product{}, err
	}
	row, err := s.queries.UpdateProduct(ctx, sqlcgen.UpdateProductParams{
		Name: product.Name, Description: product.Description, Brand: product.Brand,
		ManufacturerPartNumber: product.ManufacturerPartNumber, Status: string(product.Status),
		Attributes: attributes, UpdatedAt: pgtype.Timestamptz{Time: product.UpdatedAt, Valid: true}, Version: product.Version,
		ID: product.ID, ExpectedVersion: expectedVersion,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		if _, getErr := s.queries.GetProduct(ctx, product.ID); errors.Is(getErr, pgx.ErrNoRows) {
			return domain.Product{}, application.ErrNotFound
		}
		return domain.Product{}, application.ErrPrecondition
	}
	if err != nil {
		return domain.Product{}, mapWriteError(err)
	}
	return productFromRow(row)
}

func (s *Store) ListProducts(ctx context.Context, status *domain.ProductStatus, offset, limit int) ([]domain.Product, bool, error) {
	fetchLimit := int32(limit + 1)
	fetchOffset := int32(offset)
	var rows []sqlcgen.Product
	var err error
	if status == nil {
		rows, err = s.queries.ListProducts(ctx, sqlcgen.ListProductsParams{LimitCount: fetchLimit, OffsetCount: fetchOffset})
	} else {
		rows, err = s.queries.ListProductsByStatus(ctx, sqlcgen.ListProductsByStatusParams{
			Status: string(*status), LimitCount: fetchLimit, OffsetCount: fetchOffset,
		})
	}
	if err != nil {
		return nil, false, err
	}
	more := len(rows) > limit
	if more {
		rows = rows[:limit]
	}
	items := make([]domain.Product, 0, len(rows))
	for _, row := range rows {
		product, err := productFromRow(row)
		if err != nil {
			return nil, false, err
		}
		items = append(items, product)
	}
	return items, more, nil
}

func (s *Store) CreateSKU(ctx context.Context, sku domain.SKU) error {
	optionValues, err := json.Marshal(sku.OptionValues)
	if err != nil {
		return err
	}
	attributes, err := json.Marshal(sku.Attributes)
	if err != nil {
		return err
	}
	_, err = s.queries.CreateSKU(ctx, sqlcgen.CreateSKUParams{
		ID: sku.ID, ProductID: sku.ProductID, Code: sku.Code, Gtin: sku.GTIN,
		Status: string(sku.Status), OptionValues: optionValues, Attributes: attributes,
		CreatedAt: pgtype.Timestamptz{Time: sku.CreatedAt, Valid: true}, UpdatedAt: pgtype.Timestamptz{Time: sku.UpdatedAt, Valid: true}, Version: sku.Version,
	})
	return mapWriteError(err)
}

func (s *Store) GetSKU(ctx context.Context, productID, skuID string) (domain.SKU, error) {
	row, err := s.queries.GetSKU(ctx, sqlcgen.GetSKUParams{ProductID: productID, ID: skuID})
	if err != nil {
		return domain.SKU{}, mapReadError(err)
	}
	return skuFromRow(row)
}

func (s *Store) UpdateSKU(ctx context.Context, sku domain.SKU, expectedVersion int64) (domain.SKU, error) {
	optionValues, err := json.Marshal(sku.OptionValues)
	if err != nil {
		return domain.SKU{}, err
	}
	attributes, err := json.Marshal(sku.Attributes)
	if err != nil {
		return domain.SKU{}, err
	}
	row, err := s.queries.UpdateSKU(ctx, sqlcgen.UpdateSKUParams{
		Code: sku.Code, Gtin: sku.GTIN, Status: string(sku.Status),
		OptionValues: optionValues, Attributes: attributes, UpdatedAt: pgtype.Timestamptz{Time: sku.UpdatedAt, Valid: true},
		Version: sku.Version, ProductID: sku.ProductID, ID: sku.ID, ExpectedVersion: expectedVersion,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		if _, getErr := s.queries.GetSKU(ctx, sqlcgen.GetSKUParams{ProductID: sku.ProductID, ID: sku.ID}); errors.Is(getErr, pgx.ErrNoRows) {
			return domain.SKU{}, application.ErrNotFound
		}
		return domain.SKU{}, application.ErrPrecondition
	}
	if err != nil {
		return domain.SKU{}, mapWriteError(err)
	}
	return skuFromRow(row)
}

func (s *Store) ListSKUs(ctx context.Context, productID string, offset, limit int) ([]domain.SKU, bool, error) {
	rows, err := s.queries.ListSKUs(ctx, sqlcgen.ListSKUsParams{
		ProductID: productID, LimitCount: int32(limit + 1), OffsetCount: int32(offset),
	})
	if err != nil {
		return nil, false, err
	}
	more := len(rows) > limit
	if more {
		rows = rows[:limit]
	}
	items := make([]domain.SKU, 0, len(rows))
	for _, row := range rows {
		sku, err := skuFromRow(row)
		if err != nil {
			return nil, false, err
		}
		items = append(items, sku)
	}
	return items, more, nil
}

func (s *Store) Load(ctx context.Context, key string) (application.CommandResult, bool, error) {
	row, err := s.queries.GetCommand(ctx, key)
	if errors.Is(err, pgx.ErrNoRows) {
		return application.CommandResult{}, false, nil
	}
	if err != nil {
		return application.CommandResult{}, false, err
	}
	result := application.CommandResult{Fingerprint: row.Fingerprint}
	switch row.ResultKind {
	case "product":
		var product domain.Product
		if err := json.Unmarshal(row.ResultPayload, &product); err != nil {
			return application.CommandResult{}, false, err
		}
		result.Product = &product
	case "sku":
		var sku domain.SKU
		if err := json.Unmarshal(row.ResultPayload, &sku); err != nil {
			return application.CommandResult{}, false, err
		}
		result.SKU = &sku
	default:
		return application.CommandResult{}, false, errors.New("unknown command journal result kind")
	}
	return result, true, nil
}

func (s *Store) Save(ctx context.Context, key string, result application.CommandResult) error {
	var kind string
	var payload []byte
	var err error
	switch {
	case result.Product != nil && result.SKU == nil:
		kind = "product"
		payload, err = json.Marshal(result.Product)
	case result.SKU != nil && result.Product == nil:
		kind = "sku"
		payload, err = json.Marshal(result.SKU)
	default:
		return errors.New("command journal result must contain exactly one resource")
	}
	if err != nil {
		return err
	}
	err = s.queries.SaveCommand(ctx, sqlcgen.SaveCommandParams{
		JournalKey: key, Fingerprint: result.Fingerprint, ResultKind: kind, ResultPayload: payload,
	})
	return mapWriteError(err)
}

func productFromRow(row sqlcgen.Product) (domain.Product, error) {
	attributes := domain.AttributeMap{}
	if len(row.Attributes) > 0 {
		if err := json.Unmarshal(row.Attributes, &attributes); err != nil {
			return domain.Product{}, err
		}
	}
	return domain.Product{
		ID: row.ID, Name: row.Name, Description: row.Description, Brand: row.Brand,
		ManufacturerPartNumber: row.ManufacturerPartNumber, Status: domain.ProductStatus(row.Status),
		Attributes: attributes, CreatedAt: row.CreatedAt.Time, UpdatedAt: row.UpdatedAt.Time, Version: row.Version,
	}, nil
}

func skuFromRow(row sqlcgen.Sku) (domain.SKU, error) {
	optionValues := map[string]string{}
	if len(row.OptionValues) > 0 {
		if err := json.Unmarshal(row.OptionValues, &optionValues); err != nil {
			return domain.SKU{}, err
		}
	}
	attributes := domain.AttributeMap{}
	if len(row.Attributes) > 0 {
		if err := json.Unmarshal(row.Attributes, &attributes); err != nil {
			return domain.SKU{}, err
		}
	}
	return domain.SKU{
		ID: row.ID, ProductID: row.ProductID, Code: row.Code, GTIN: row.Gtin,
		Status: domain.SKUStatus(row.Status), OptionValues: optionValues, Attributes: attributes,
		CreatedAt: row.CreatedAt.Time, UpdatedAt: row.UpdatedAt.Time, Version: row.Version,
	}, nil
}

func mapReadError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return application.ErrNotFound
	}
	return err
}

func mapWriteError(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			return application.ErrConflict
		case "23503":
			return application.ErrNotFound
		}
	}
	return err
}
