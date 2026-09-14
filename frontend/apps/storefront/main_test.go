package main

import (
	"github.com/dst-red-Wire/ecommerce-1/frontend/internal/web"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRoutes(t *testing.T) {
	h := web.App{Name: "Storefront", Admin: false}.Handler()
	for _, tc := range []struct {
		method, path string
		want         int
	}{{"GET", "/", 200}, {"GET", "/error", 503}, {"GET", "/missing", 404}} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("%s: %d", tc.path, w.Code)
		}
		if v := w.Header().Get("Content-Security-Policy"); !strings.Contains(v, "frame-ancestors 'none'") {
			t.Fatalf("CSP: %q", v)
		}
		if w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("nosniff")
		}
	}
}
func TestHTMX(t *testing.T) {
	h := web.App{Name: "Storefront", Admin: false}.Handler()
	r := httptest.NewRequest("GET", "/catalog", nil)
	r.Header.Set("HX-Request", "true")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if strings.Contains(w.Body.String(), "<!doctype") || !strings.Contains(w.Body.String(), "<section") {
		t.Fatalf("not fragment: %s", w.Body.String())
	}
}
func TestRedirect(t *testing.T) {
	h := web.App{Name: "Storefront", Admin: false}.Handler()
	r := httptest.NewRequest("POST", "/cart/items", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d", w.Code)
	}
}
