//go:build integration

package postgres_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"net/url"
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
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

const postgresTestImage = "docker.io/library/postgres:17.10-alpine3.22@sha256:b02d9b5bcf608c2719da32cdabee274a33841202487fd5dc9b065b63f886753f"

func TestPostgresPersistenceAndIdempotencySurviveRestart(t *testing.T) {
	ctx := context.Background()
	config := testcontainers.ReadConfig().Config
	ip, err := localQualificationAddress(os.Getenv("DOCKER_HOST"), config.TestcontainersHost, config.Host)
	if err != nil {
		t.Fatal(err)
	}
	passwordBytes := make([]byte, 32)
	if _, err := rand.Read(passwordBytes); err != nil {
		t.Fatal("generate PostgreSQL credential")
	}
	password := hex.EncodeToString(passwordBytes)
	safeError := func(err error) string { return strings.ReplaceAll(err.Error(), password, "[REDACTED]") }
	container, err := tcpostgres.Run(
		ctx,
		postgresTestImage,
		tcpostgres.WithDatabase("product"),
		tcpostgres.WithUsername("product"),
		tcpostgres.WithPassword(password),
		testcontainers.WithHostConfigModifier(func(config *container.HostConfig) {
			config.PortBindings = network.PortMap{network.MustParsePort("5432/tcp"): []network.PortBinding{{HostIP: ip, HostPort: ""}}}
		}),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Fatalf("start postgres: %s", safeError(err))
	}
	t.Cleanup(func() {
		if err := testcontainers.TerminateContainer(container); err != nil {
			t.Errorf("terminate postgres: %v", safeError(err))
		}
	})

	inspection, err := container.Inspect(ctx)
	if err != nil {
		t.Fatalf("inspect PostgreSQL publication: %s", safeError(err))
	}
	bindings := inspection.NetworkSettings.Ports[network.MustParsePort("5432/tcp")]
	if len(bindings) != 1 || bindings[0].HostIP != ip || bindings[0].HostPort == "" {
		t.Fatal("PostgreSQL publication does not match the authorized daemon interface")
	}

	requirePinnedRyuk(t, container.SessionID())

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", safeError(err))
	}
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect for migration: %v", safeError(err))
	}
	if err := migrations.Up(ctx, conn); err != nil {
		_ = conn.Close(ctx)
		t.Fatalf("migrate: %v", safeError(err))
	}
	if err := migrations.Up(ctx, conn); err != nil {
		_ = conn.Close(ctx)
		t.Fatalf("second migrate should be idempotent: %v", safeError(err))
	}
	if err := conn.Close(ctx); err != nil {
		t.Fatalf("close migration connection: %v", safeError(err))
	}

	newService := func() (*application.Service, *pgxpool.Pool) {
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatalf("new pool: %v", safeError(err))
		}
		if err := pool.Ping(ctx); err != nil {
			pool.Close()
			t.Fatalf("ping pool: %v", safeError(err))
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
		t.Fatalf("create product: %v", safeError(err))
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
		t.Fatalf("replay product create after restart: %v", safeError(err))
	}
	if !replayed || replayedProduct.ID != product.ID {
		pool.Close()
		t.Fatalf("durable idempotency mismatch: replayed=%v id=%s want=%s", replayed, replayedProduct.ID, product.ID)
	}

	newName := "Persistent NOMA Lamp v2"
	updated, replayed, err := service.UpdateProduct(ctx, product.ID, "update-product-001", application.ETag(product.Version), application.UpdateProductInput{Name: &newName})
	if err != nil {
		pool.Close()
		t.Fatalf("update product: %v", safeError(err))
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
		t.Fatalf("replay update after restart: %v", safeError(err))
	}
	if !replayed || replayedUpdate.Version != updated.Version || replayedUpdate.Name != newName {
		t.Fatalf("durable update replay mismatch: replayed=%v version=%d name=%q", replayed, replayedUpdate.Version, replayedUpdate.Name)
	}

	sku, replayed, err := service.CreateSKU(ctx, product.ID, "create-sku-0001", application.CreateSKUInput{
		Code:         "NOMA-LAMP-BLK",
		OptionValues: map[string]string{"color": "black"},
	})
	if err != nil {
		t.Fatalf("create sku: %v", safeError(err))
	}
	if replayed || sku.ProductID != product.ID {
		t.Fatalf("unexpected sku result: replayed=%v product=%s", replayed, sku.ProductID)
	}

	items, more, err := service.ListSKUs(ctx, product.ID, 0, 20)
	if err != nil {
		t.Fatalf("list skus: %v", safeError(err))
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

// Reject remote execution before Testcontainers can create its separately managed
// Ryuk container, whose control-port interface cannot be constrained by this fixture.
func localQualificationAddress(raw string, alternatives ...string) (netip.Addr, error) {
	for _, alternative := range alternatives {
		if alternative != "" {
			if _, err := localQualificationAddress(alternative); err != nil {
				return netip.Addr{}, err
			}
		}
	}
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Path == "" || (endpoint.Scheme != "unix" && endpoint.Scheme != "npipe") || (endpoint.Host != "" && endpoint.Host != ".") {
		return netip.Addr{}, fmt.Errorf("Product integration requires an explicit local Docker socket: remote Ryuk interface binding cannot be enforced")
	}
	return netip.MustParseAddr("127.0.0.1"), nil
}

func TestQualificationRejectsRemoteRyukBeforeCreation(t *testing.T) {
	for _, endpoint := range []string{"", "tcp://daemon:2376", "http://daemon:2375", "https://daemon:2376", "ssh://user@daemon", "tcp://127.0.0.1:2376", "npipe://remote/pipe/docker_engine"} {
		t.Run(endpoint, func(t *testing.T) {
			if _, err := localQualificationAddress(endpoint); err == nil {
				t.Fatal("remote or unresolved daemon accepted")
			}
		})
	}
	for _, alternative := range []string{"tcp://daemon:2376", "https://daemon:2376", "ssh://daemon"} {
		if _, err := localQualificationAddress("unix:///var/run/docker.sock", alternative); err == nil {
			t.Fatal("remote Testcontainers property override accepted")
		}
	}
	for _, endpoint := range []string{"unix:///var/run/docker.sock", "npipe:////./pipe/docker_engine"} {
		if address, err := localQualificationAddress(endpoint); err != nil || !address.IsLoopback() {
			t.Fatalf("local endpoint rejected: %v", err)
		}
	}
}
