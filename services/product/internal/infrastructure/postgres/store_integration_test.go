//go:build integration

package postgres_test

import (
	"context"
	"testing"

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
		return application.NewService(store, store), pool
	}

	service, pool := newService()
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
}
