//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/application"
	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/domain"
	productpostgres "github.com/dst-red-Wire/ecommerce-1/services/product/internal/infrastructure/postgres"
	"github.com/dst-red-Wire/ecommerce-1/services/product/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

const postgresTestImage = "docker.io/library/postgres:17.10-alpine3.22@sha256:b02d9b5bcf608c2719da32cdabee274a33841202487fd5dc9b065b63f886753f"

func TestPostgresPersistenceAndIdempotencySurviveRestart(t *testing.T) {
	ctx := context.Background()
	container, err := tcpostgres.Run(
		ctx,
		postgresTestImage,
		tcpostgres.WithDatabase("product"),
		tcpostgres.WithUsername("product"),
		tcpostgres.WithPassword("product-test-only"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	t.Cleanup(func() {
		if err := testcontainers.TerminateContainer(container); err != nil {
			t.Errorf("terminate postgres: %v", err)
		}
	})

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}
	preMigrationPool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("new pre-migration pool: %v", err)
	}
	if err := productpostgres.NewStore(preMigrationPool).Ready(ctx); err == nil {
		preMigrationPool.Close()
		t.Fatal("unmigrated database must not report ready")
	}
	preMigrationPool.Close()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect for migration: %v", err)
	}
	if err := migrations.Up(ctx, conn); err != nil {
		_ = conn.Close(ctx)
		t.Fatalf("migrate: %v", err)
	}
	if err := migrations.Up(ctx, conn); err != nil {
		_ = conn.Close(ctx)
		t.Fatalf("second migrate should be idempotent: %v", err)
	}
	if err := conn.Close(ctx); err != nil {
		t.Fatalf("close migration connection: %v", err)
	}

	newService := func() (*application.Service, *pgxpool.Pool) {
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatalf("new pool: %v", err)
		}
		if err := pool.Ping(ctx); err != nil {
			pool.Close()
			t.Fatalf("ping pool: %v", err)
		}
		store := productpostgres.NewStore(pool)
		return application.NewService(store), pool
	}

	service, pool := newService()
	if err := productpostgres.NewStore(pool).Ready(ctx); err != nil {
		pool.Close()
		t.Fatalf("migrated database must report ready: %v", err)
	}
	product, replayed, err := service.CreateProduct(ctx, "create-product-001", application.CreateProductInput{
		Name:       "Persistent NOMA Lamp",
		Attributes: domain.AttributeMap{"material": "metal"},
	})
	if err != nil {
		pool.Close()
		t.Fatalf("create product: %v", err)
	}
	if replayed {
		pool.Close()
		t.Fatal("first create must not be replayed")
	}
	pool.Close()

	service, pool = newService()
	replayedProduct, replayed, err := service.CreateProduct(ctx, "create-product-001", application.CreateProductInput{
		Name:       "Persistent NOMA Lamp",
		Attributes: domain.AttributeMap{"material": "metal"},
	})
	if err != nil {
		pool.Close()
		t.Fatalf("replay product create after restart: %v", err)
	}
	if !replayed || replayedProduct.ID != product.ID {
		pool.Close()
		t.Fatalf("durable idempotency mismatch: replayed=%v id=%s want=%s", replayed, replayedProduct.ID, product.ID)
	}

	newName := "Persistent NOMA Lamp v2"
	updated, replayed, err := service.UpdateProduct(ctx, product.ID, "update-product-001", application.ETag(product.Version), application.UpdateProductInput{Name: &newName})
	if err != nil {
		pool.Close()
		t.Fatalf("update product: %v", err)
	}
	if replayed || updated.Version != product.Version+1 {
		pool.Close()
		t.Fatalf("unexpected first update result: replayed=%v version=%d", replayed, updated.Version)
	}
	pool.Close()

	service, pool = newService()
	t.Cleanup(pool.Close)
	replayedUpdate, replayed, err := service.UpdateProduct(ctx, product.ID, "update-product-001", application.ETag(product.Version), application.UpdateProductInput{Name: &newName})
	if err != nil {
		t.Fatalf("replay update after restart: %v", err)
	}
	if !replayed || replayedUpdate.Version != updated.Version || replayedUpdate.Name != newName {
		t.Fatalf("durable update replay mismatch: replayed=%v version=%d name=%q", replayed, replayedUpdate.Version, replayedUpdate.Name)
	}

	sku, replayed, err := service.CreateSKU(ctx, product.ID, "create-sku-0001", application.CreateSKUInput{
		Code:         "NOMA-LAMP-BLK",
		OptionValues: map[string]string{"color": "black"},
	})
	if err != nil {
		t.Fatalf("create sku: %v", err)
	}
	if replayed || sku.ProductID != product.ID {
		t.Fatalf("unexpected sku result: replayed=%v product=%s", replayed, sku.ProductID)
	}

	items, more, err := service.ListSKUs(ctx, product.ID, 0, 20)
	if err != nil {
		t.Fatalf("list skus: %v", err)
	}
	if more || len(items) != 1 || items[0].ID != sku.ID {
		t.Fatalf("unexpected persisted SKU list: more=%v count=%d", more, len(items))
	}

	var outboxCount int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM outbox_events").Scan(&outboxCount); err != nil {
		t.Fatalf("count outbox events: %v", err)
	}
	if outboxCount != 3 {
		t.Fatalf("expected one event per committed command and none for replays, got %d", outboxCount)
	}

	store := productpostgres.NewStore(pool)
	claimed, err := store.Claim(ctx, time.Now().UTC().Add(time.Second), time.Now().UTC().Add(time.Minute), 10, 5)
	if err != nil {
		t.Fatalf("claim outbox events: %v", err)
	}
	var firstProductEvent string
	for _, event := range claimed {
		if event.AggregateID == product.ID {
			if firstProductEvent != "" || event.Type != application.EventProductCreated {
				t.Fatalf("later event for product aggregate was claimed before its predecessor: %+v", claimed)
			}
			firstProductEvent = event.ID
		}
	}
	if firstProductEvent == "" {
		t.Fatalf("oldest product event was not claimed: %+v", claimed)
	}
	if err := store.MarkPublished(ctx, firstProductEvent, time.Now().UTC()); err != nil {
		t.Fatalf("mark oldest product event published: %v", err)
	}
	next, err := store.Claim(ctx, time.Now().UTC().Add(time.Second), time.Now().UTC().Add(time.Minute), 10, 5)
	if err != nil {
		t.Fatalf("claim successor event: %v", err)
	}
	if len(next) != 1 || next[0].AggregateID != product.ID || next[0].Type != application.EventProductUpdated {
		t.Fatalf("expected product update only after create acknowledgement, got %+v", next)
	}
	invalidProduct := domain.Product{
		ID: "57f2a602-5435-4ce4-a12e-ae38697bc547", Name: "Must roll back", Status: domain.ProductStatusDraft,
		Attributes: domain.AttributeMap{}, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), Version: 1,
	}
	invalidEvent := application.OutboxEvent{
		ID: "3c645042-dd73-42fa-928a-5677f09158af", Type: "product.ProductCreated.v1", SchemaVersion: 1,
		OccurredAtUTC: time.Now().UTC(), Producer: "product", AggregateType: "product", AggregateID: "not-a-uuid",
		AggregateVersion: 1,
		CorrelationID:    "atomicity-proof", CausationID: "atomicity-proof", HomeSite: "test", Product: &invalidProduct,
	}
	err = store.CreateProduct(ctx, "atomicity-proof-command", application.CommandResult{
		Fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Product: &invalidProduct,
	}, invalidProduct, invalidEvent)
	if err == nil {
		t.Fatal("expected invalid outbox insert to roll back the transaction")
	}
	if _, err := store.GetProduct(ctx, invalidProduct.ID); !errors.Is(err, application.ErrNotFound) {
		t.Fatalf("business mutation survived failed outbox write: %v", err)
	}
	if _, found, err := store.LoadCommand(ctx, "atomicity-proof-command"); err != nil || found {
		t.Fatalf("command journal survived failed outbox write: found=%v err=%v", found, err)
	}
}
