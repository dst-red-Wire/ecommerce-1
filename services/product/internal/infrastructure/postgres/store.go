package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/application"
	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/domain"
	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/infrastructure/postgres/sqlcgen"
	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/outbox"
	productprotobuf "github.com/dst-red-Wire/ecommerce-1/services/product/internal/protobuf"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool    *pgxpool.Pool
	queries *sqlcgen.Queries
	encoder productprotobuf.EventEncoder
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool, queries: sqlcgen.New(pool), encoder: productprotobuf.EventEncoder{}}
}

func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

func (s *Store) Ready(ctx context.Context) error {
	ready, err := s.queries.CheckReadiness(ctx)
	if err != nil {
		return err
	}
	if !ready {
		return errors.New("product database schema is not ready")
	}
	return nil
}

func (s *Store) CreateProduct(ctx context.Context, key string, result application.CommandResult, product domain.Product, event application.OutboxEvent) error {
	attributes, err := json.Marshal(product.Attributes)
	if err != nil {
		return err
	}
	return s.transaction(ctx, key, result, event, func(queries *sqlcgen.Queries) error {
		_, err := queries.CreateProduct(ctx, sqlcgen.CreateProductParams{
			ID: product.ID, Name: product.Name, Description: product.Description,
			Brand: product.Brand, ManufacturerPartNumber: product.ManufacturerPartNumber,
			Status: string(product.Status), Attributes: attributes,
			CreatedAt: timestamp(product.CreatedAt), UpdatedAt: timestamp(product.UpdatedAt), Version: product.Version,
		})
		return err
	})
}

func (s *Store) GetProduct(ctx context.Context, id string) (domain.Product, error) {
	row, err := s.queries.GetProduct(ctx, id)
	if err != nil {
		return domain.Product{}, mapReadError(err)
	}
	return productFromRow(row)
}

func (s *Store) UpdateProduct(ctx context.Context, key string, result application.CommandResult, product domain.Product, expectedVersion int64, event application.OutboxEvent) (domain.Product, error) {
	attributes, err := json.Marshal(product.Attributes)
	if err != nil {
		return domain.Product{}, err
	}
	var updated domain.Product
	err = s.transaction(ctx, key, result, event, func(queries *sqlcgen.Queries) error {
		row, updateErr := queries.UpdateProduct(ctx, sqlcgen.UpdateProductParams{
			Name: product.Name, Description: product.Description, Brand: product.Brand,
			ManufacturerPartNumber: product.ManufacturerPartNumber, Status: string(product.Status),
			Attributes: attributes, UpdatedAt: timestamp(product.UpdatedAt), Version: product.Version,
			ID: product.ID, ExpectedVersion: expectedVersion,
		})
		if errors.Is(updateErr, pgx.ErrNoRows) {
			if _, getErr := queries.GetProduct(ctx, product.ID); errors.Is(getErr, pgx.ErrNoRows) {
				return application.ErrNotFound
			}
			return application.ErrPrecondition
		}
		if updateErr != nil {
			return updateErr
		}
		updated, updateErr = productFromRow(row)
		return updateErr
	})
	if err != nil {
		return domain.Product{}, err
	}
	return updated, nil
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

func (s *Store) CreateSKU(ctx context.Context, key string, result application.CommandResult, sku domain.SKU, event application.OutboxEvent) error {
	optionValues, err := json.Marshal(sku.OptionValues)
	if err != nil {
		return err
	}
	attributes, err := json.Marshal(sku.Attributes)
	if err != nil {
		return err
	}
	return s.transaction(ctx, key, result, event, func(queries *sqlcgen.Queries) error {
		_, err := queries.CreateSKU(ctx, sqlcgen.CreateSKUParams{
			ID: sku.ID, ProductID: sku.ProductID, Code: sku.Code, Gtin: sku.GTIN,
			Status: string(sku.Status), OptionValues: optionValues, Attributes: attributes,
			CreatedAt: timestamp(sku.CreatedAt), UpdatedAt: timestamp(sku.UpdatedAt), Version: sku.Version,
		})
		return err
	})
}

func (s *Store) GetSKU(ctx context.Context, productID, skuID string) (domain.SKU, error) {
	row, err := s.queries.GetSKU(ctx, sqlcgen.GetSKUParams{ProductID: productID, ID: skuID})
	if err != nil {
		return domain.SKU{}, mapReadError(err)
	}
	return skuFromRow(row)
}

func (s *Store) UpdateSKU(ctx context.Context, key string, result application.CommandResult, sku domain.SKU, expectedVersion int64, event application.OutboxEvent) (domain.SKU, error) {
	optionValues, err := json.Marshal(sku.OptionValues)
	if err != nil {
		return domain.SKU{}, err
	}
	attributes, err := json.Marshal(sku.Attributes)
	if err != nil {
		return domain.SKU{}, err
	}
	var updated domain.SKU
	err = s.transaction(ctx, key, result, event, func(queries *sqlcgen.Queries) error {
		row, updateErr := queries.UpdateSKU(ctx, sqlcgen.UpdateSKUParams{
			Code: sku.Code, Gtin: sku.GTIN, Status: string(sku.Status),
			OptionValues: optionValues, Attributes: attributes, UpdatedAt: timestamp(sku.UpdatedAt),
			Version: sku.Version, ProductID: sku.ProductID, ID: sku.ID, ExpectedVersion: expectedVersion,
		})
		if errors.Is(updateErr, pgx.ErrNoRows) {
			if _, getErr := queries.GetSKU(ctx, sqlcgen.GetSKUParams{ProductID: sku.ProductID, ID: sku.ID}); errors.Is(getErr, pgx.ErrNoRows) {
				return application.ErrNotFound
			}
			return application.ErrPrecondition
		}
		if updateErr != nil {
			return updateErr
		}
		updated, updateErr = skuFromRow(row)
		return updateErr
	})
	if err != nil {
		return domain.SKU{}, err
	}
	return updated, nil
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

func (s *Store) LoadCommand(ctx context.Context, key string) (application.CommandResult, bool, error) {
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

func saveCommand(ctx context.Context, queries *sqlcgen.Queries, key string, result application.CommandResult) error {
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
	err = queries.SaveCommand(ctx, sqlcgen.SaveCommandParams{
		JournalKey: key, Fingerprint: result.Fingerprint, ResultKind: kind, ResultPayload: payload,
	})
	return err
}

func (s *Store) transaction(
	ctx context.Context,
	key string,
	result application.CommandResult,
	event application.OutboxEvent,
	mutate func(*sqlcgen.Queries) error,
) error {
	payload, err := s.encoder.Encode(event)
	if err != nil {
		return err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	queries := s.queries.WithTx(tx)
	if err := saveCommand(ctx, queries, key, result); err != nil {
		return mapWriteError(err)
	}
	if err := mutate(queries); err != nil {
		return mapWriteError(err)
	}
	if err := queries.InsertOutboxEvent(ctx, sqlcgen.InsertOutboxEventParams{
		EventID: event.ID, EventType: event.Type, SchemaVersion: int32(event.SchemaVersion),
		OccurredAtUtc: timestamp(event.OccurredAtUTC), Producer: event.Producer,
		AggregateType: event.AggregateType, AggregateID: event.AggregateID, AggregateVersion: event.AggregateVersion,
		CorrelationID: event.CorrelationID, CausationID: event.CausationID,
		HomeSite: event.HomeSite, Payload: payload,
	}); err != nil {
		return mapWriteError(err)
	}
	return tx.Commit(ctx)
}

func (s *Store) Claim(ctx context.Context, availableBefore, leaseUntil time.Time, limit, maxAttempts int) ([]outbox.Event, error) {
	rows, err := s.queries.ClaimOutboxEvents(ctx, sqlcgen.ClaimOutboxEventsParams{
		PAvailableBefore: timestamp(availableBefore), PLeaseUntil: timestamp(leaseUntil),
		PLimitCount: int32(limit), PMaxAttempts: int32(maxAttempts),
	})
	if err != nil {
		return nil, err
	}
	events := make([]outbox.Event, 0, len(rows))
	for _, row := range rows {
		events = append(events, outbox.Event{
			ID: row.EventID, Type: row.EventType, SchemaVersion: int(row.SchemaVersion),
			AggregateID: row.AggregateID, Payload: row.Payload, AttemptCount: int(row.AttemptCount),
		})
	}
	return events, nil
}

func (s *Store) MarkPublished(ctx context.Context, eventID string, publishedAt time.Time) error {
	return s.queries.MarkOutboxPublished(ctx, sqlcgen.MarkOutboxPublishedParams{
		PEventID: eventID, PPublishedAt: timestamp(publishedAt),
	})
}

func (s *Store) Reschedule(ctx context.Context, eventID string, availableAt time.Time, lastError string) error {
	return s.queries.RescheduleOutboxEvent(ctx, sqlcgen.RescheduleOutboxEventParams{
		PEventID: eventID, PAvailableAt: timestamp(availableAt), PLastError: lastError,
	})
}

func (s *Store) MoveToDeadLetter(ctx context.Context, eventID, lastError string) error {
	return s.queries.MoveOutboxEventToDeadLetter(ctx, sqlcgen.MoveOutboxEventToDeadLetterParams{
		PEventID: eventID, PLastError: lastError,
	})
}

func timestamp(value time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: value, Valid: true}
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
