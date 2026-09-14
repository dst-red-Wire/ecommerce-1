package main

import (
	"github.com/dst-red-Wire/ecommerce-1/frontend/internal/web"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	server := &http.Server{
		Addr:              addr,
		Handler:           web.App{Name: "Storefront", Admin: false}.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}
