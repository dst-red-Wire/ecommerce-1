package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/dst-red-Wire/ecommerce-1/services/product/migrations"
	"github.com/jackc/pgx/v5"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	dsn := os.Getenv("PRODUCT_DATABASE_URL")
	if dsn == "" {
		logger.Error("PRODUCT_DATABASE_URL is required")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		logger.Error("connect product database failed", "error", err.Error())
		os.Exit(1)
	}
	defer func() {
		if err := conn.Close(context.Background()); err != nil {
			logger.Error("close product database failed", "error", err.Error())
		}
	}()
	if err := migrations.Up(ctx, conn); err != nil {
		logger.Error("migrate product database failed", "error", err.Error())
		os.Exit(1)
	}
	logger.Info("product database migrations complete")
}
