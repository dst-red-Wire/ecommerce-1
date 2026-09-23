package grpc_test

import (
	"context"
	"net"
	"testing"

	productv1 "github.com/dst-red-Wire/ecommerce-1/services/product/api/generated/product/v1"
	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/application"
	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/infrastructure/memory"
	grpctransport "github.com/dst-red-Wire/ecommerce-1/services/product/internal/transport/grpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func TestGRPCUsesApplicationIdempotencyAndEmitsOneDurableEvent(t *testing.T) {
	store := memory.NewStore()
	listener := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	productv1.RegisterProductServiceServer(grpcServer, grpctransport.NewServer(application.NewService(store)))
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(grpcServer.Stop)
	connection, err := grpc.NewClient("passthrough:///product", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(
		func(context.Context, string) (net.Conn, error) { return listener.Dial() },
	))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	client := productv1.NewProductServiceClient(connection)
	request := &productv1.CreateProductRequest{IdempotencyKey: "grpc-create-0001", Name: "Lamp", Status: "active"}
	created, err := client.CreateProduct(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := client.CreateProduct(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.GetProduct().GetId() != created.GetProduct().GetId() || !replayed.GetReplayed() {
		t.Fatalf("unexpected replay: created=%+v replayed=%+v", created, replayed)
	}
	if events := store.OutboxEvents(); len(events) != 1 || events[0].Type != "product.ProductCreated.v1" {
		t.Fatalf("expected one durable event, got %+v", events)
	}
}

func TestGRPCUpdateSKUCanClearOptionValues(t *testing.T) {
	store := memory.NewStore()
	listener := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	productv1.RegisterProductServiceServer(grpcServer, grpctransport.NewServer(application.NewService(store)))
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(grpcServer.Stop)
	connection, err := grpc.NewClient("passthrough:///product", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(
		func(context.Context, string) (net.Conn, error) { return listener.Dial() },
	))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	client := productv1.NewProductServiceClient(connection)
	product, err := client.CreateProduct(context.Background(), &productv1.CreateProductRequest{
		IdempotencyKey: "grpc-product-options", Name: "Lamp", Status: "active",
	})
	if err != nil {
		t.Fatal(err)
	}
	sku, err := client.CreateSKU(context.Background(), &productv1.CreateSKURequest{
		ProductId: product.GetProduct().GetId(), IdempotencyKey: "grpc-sku-options", Code: "LAMP-BLACK",
		OptionValues: map[string]string{"color": "black"},
	})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := client.UpdateSKU(context.Background(), &productv1.UpdateSKURequest{
		ProductId: product.GetProduct().GetId(), Id: sku.GetSku().GetId(),
		IdempotencyKey: "grpc-clear-options", IfMatch: application.ETag(sku.GetSku().GetVersion()),
		OptionValues: &productv1.StringMap{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if values := updated.GetSku().GetOptionValues(); len(values) != 0 {
		t.Fatalf("expected option values to be cleared, got %v", values)
	}
}
