package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/dst-red-Wire/ecommerce-1/services/product/migrations"
	"github.com/jackc/pgx/v5"
)

func main() {
	dsn := os.Getenv("PRODUCT_DATABASE_URL")
	if dsn == "" {
		log.Fatal("PRODUCT_DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		log.Fatalf("connect product database: %v", err)
	}
	defer func() {
		if err := conn.Close(context.Background()); err != nil {
			log.Printf("close product database: %v", err)
		}
	}()
	if err := migrations.Up(ctx, conn); err != nil {
		log.Fatalf("migrate product database: %v", err)
	}
	log.Print("product database migrations: PASS")
}
