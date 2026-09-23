package application_test

import (
	"context"
	"sync"
	"testing"

	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/application"
	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/infrastructure/memory"
)

func TestConcurrentReplayCommitsOneMutationAndOneEvent(t *testing.T) {
	store := memory.NewStore()
	service := application.NewService(store)
	const workers = 16
	ids := make(chan string, workers)
	errors := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			product, _, err := service.CreateProduct(context.Background(), "concurrent-product-0001", application.CreateProductInput{Name: "Lamp"})
			if err != nil {
				errors <- err
				return
			}
			ids <- product.ID
		}()
	}
	wait.Wait()
	close(ids)
	close(errors)
	for err := range errors {
		t.Errorf("concurrent command failed: %v", err)
	}
	var expected string
	for id := range ids {
		if expected == "" {
			expected = id
		}
		if id != expected {
			t.Fatalf("replay returned multiple aggregate IDs: %s != %s", id, expected)
		}
	}
	products, more, err := service.ListProducts(context.Background(), nil, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if more || len(products) != 1 || len(store.OutboxEvents()) != 1 {
		t.Fatalf("expected one mutation and event: products=%d events=%d", len(products), len(store.OutboxEvents()))
	}
}
