package main

import (
	"github.com/dst-red-Wire/ecommerce-1/frontend/internal/web"
	"log"
	"net/http"
	"os"
)

func main() {
	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Fatal(http.ListenAndServe(addr, web.App{Name: "Storefront", Admin: false}.Handler()))
}
