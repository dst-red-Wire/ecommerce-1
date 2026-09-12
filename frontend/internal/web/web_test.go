package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLegacyStorefrontRoutesRedirectToCanonicalRoutes(t *testing.T) {
	tests := map[string]string{
		"/catalogue":       "/catalog",
		"/produit/example": "/products/example",
	}
	for path, location := range tests {
		t.Run(path, func(t *testing.T) {
			response := httptest.NewRecorder()
			App{Name: "Storefront"}.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			if response.Code != http.StatusPermanentRedirect || response.Header().Get("Location") != location {
				t.Fatalf("redirect = (%d, %q), want (%d, %q)", response.Code, response.Header().Get("Location"), http.StatusPermanentRedirect, location)
			}
		})
	}
}

func TestRepresentationsVaryOnHXRequest(t *testing.T) {
	for _, hx := range []string{"", "true"} {
		t.Run("HX-Request="+hx, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/catalog", nil)
			request.Header.Set("HX-Request", hx)
			response := httptest.NewRecorder()
			App{Name: "Storefront"}.Handler().ServeHTTP(response, request)
			if got := response.Header().Values("Vary"); len(got) != 1 || got[0] != "HX-Request" {
				t.Fatalf("Vary = %q, want [HX-Request]", got)
			}
		})
	}
}

func TestStockMutationIsAdminOnly(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/products/example/stock", nil)
	storefront := httptest.NewRecorder()
	App{Name: "Storefront"}.Handler().ServeHTTP(storefront, request)
	if storefront.Code != http.StatusMethodNotAllowed {
		t.Fatalf("storefront stock mutation status = %d, want %d", storefront.Code, http.StatusMethodNotAllowed)
	}

	admin := httptest.NewRecorder()
	App{Name: "Admin", Admin: true}.Handler().ServeHTTP(admin, request)
	if admin.Code != http.StatusSeeOther {
		t.Fatalf("admin stock mutation status = %d, want %d", admin.Code, http.StatusSeeOther)
	}
}
