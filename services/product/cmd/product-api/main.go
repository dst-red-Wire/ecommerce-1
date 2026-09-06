package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/application"
	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/infrastructure/memory"
	productpostgres "github.com/dst-red-Wire/ecommerce-1/services/product/internal/infrastructure/postgres"
	resttransport "github.com/dst-red-Wire/ecommerce-1/services/product/internal/transport/rest"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	repo, journal, readiness, closeStore, err := persistence(ctx)
	if err != nil {
		log.Fatalf("product persistence: %v", err)
	}
	defer closeStore()

	service := application.NewService(repo, journal)
	handler := resttransport.NewHandlerWithReadiness(service, readiness)

	addr := os.Getenv("PRODUCT_HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("product API listening on %s", addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("product API failed: %v", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("product API shutdown: %v", err)
	}
}

func persistence(ctx context.Context) (application.Repository, application.CommandJournal, resttransport.Readiness, func(), error) {
	storage := os.Getenv("PRODUCT_STORAGE")
	if storage == "" {
		storage = "postgres"
	}
	switch storage {
	case "memory":
		store := memory.NewStore()
		return store, store, nil, func() {}, nil
	case "postgres":
		dsn := os.Getenv("PRODUCT_DATABASE_URL")
		if dsn == "" {
			return nil, nil, nil, func() {}, fmt.Errorf("PRODUCT_DATABASE_URL is required when PRODUCT_STORAGE=postgres")
		}
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			return nil, nil, nil, func() {}, err
		}
		if err := pool.Ping(ctx); err != nil {
			pool.Close()
			return nil, nil, nil, func() {}, err
		}
		store := productpostgres.NewStore(pool)
		return store, store, store.Ping, pool.Close, nil
	default:
		return nil, nil, nil, func() {}, fmt.Errorf("unsupported PRODUCT_STORAGE %q", storage)
	}
}
