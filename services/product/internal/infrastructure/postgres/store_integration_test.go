//go:build integration

package postgres_test

import (
	"context"
	"os"
	"os/exec"
	"strings"
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

	requirePinnedRyuk(t, container.SessionID())

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

// Testcontainers Go 0.44 hardcodes Ryuk's tag and ignores RYUK_CONTAINER_IMAGE.
// Check the running session's image ID too, so retagging after preflight cannot
// produce a successful qualification with an unapproved reaper.
func requirePinnedRyuk(t *testing.T, session string) {
	t.Helper()
	image := os.Getenv("ECOMMERCE_RYUK_IMAGE")
	if image == "" {
		image = "docker.io/testcontainers/ryuk:0.14.0@sha256:7c1a8a9a47c780ed0f983770a662f80deb115d95cce3e2daa3d12115b8cd28f0"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	docker := func(args ...string) string {
		t.Helper()
		output, err := exec.CommandContext(ctx, "docker", args...).Output()
		if err != nil {
			t.Fatalf("verify running Ryuk image: %v", err)
		}
		return strings.TrimSpace(string(output))
	}
	expected := docker("image", "inspect", image, "--format", "{{.Id}}")
	if !strings.HasPrefix(expected, "sha256:") {
		t.Fatal("pinned Ryuk image identity is absent")
	}
	ids := strings.Fields(docker("ps", "--quiet", "--filter", "label=org.testcontainers.sessionId="+session, "--filter", "label=org.testcontainers.ryuk=true"))
	if len(ids) != 1 {
		t.Fatalf("expected one running Ryuk for session %s, got %d", session, len(ids))
	}
	if actual := docker("inspect", ids[0], "--format", "{{.Image}}"); actual != expected {
		t.Fatalf("running Ryuk image mismatch: got %s, want %s", actual, expected)
	}
	t.Logf("Ryuk running image matches pinned digest: %s", image)
}
