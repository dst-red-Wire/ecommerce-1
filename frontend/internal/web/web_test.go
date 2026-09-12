package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

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
