package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStorefrontPurchaseFlowIsNavigable(t *testing.T) {
	handler := App{Name: "Storefront"}.Handler()

	catalog := httptest.NewRecorder()
	handler.ServeHTTP(catalog, httptest.NewRequest(http.MethodGet, "/catalog", nil))
	if catalog.Code != http.StatusOK || !strings.Contains(catalog.Body.String(), `href="/products/m1-demo"`) {
		t.Fatalf("catalog does not link to a usable product: status=%d body=%s", catalog.Code, catalog.Body.String())
	}

	product := httptest.NewRecorder()
	handler.ServeHTTP(product, httptest.NewRequest(http.MethodGet, "/products/m1-demo", nil))
	body := product.Body.String()
	for _, control := range []string{`method="post"`, `action="/cart/items"`, `hx-post="/cart/items"`, `hx-target="#cart-count"`} {
		if product.Code != http.StatusOK || !strings.Contains(body, control) {
			t.Fatalf("product detail does not expose %q: status=%d body=%s", control, product.Code, body)
		}
	}

	hxRequest := httptest.NewRequest(http.MethodPost, "/cart/items", io.NopCloser(strings.NewReader("product_id=m1-demo")))
	hxRequest.Header.Set("HX-Request", "true")
	hxResponse := httptest.NewRecorder()
	handler.ServeHTTP(hxResponse, hxRequest)
	if hxResponse.Code != http.StatusOK || !strings.Contains(hxResponse.Body.String(), `id="cart-count">1 item`) {
		t.Fatalf("HTMX cart update = (%d, %q), want updated cart count", hxResponse.Code, hxResponse.Body.String())
	}

	redirect := httptest.NewRecorder()
	handler.ServeHTTP(redirect, httptest.NewRequest(http.MethodPost, "/cart/items", nil))
	if redirect.Code != http.StatusSeeOther || redirect.Header().Get("Location") != "/cart" {
		t.Fatalf("normal cart submit = (%d, %q), want (303, /cart)", redirect.Code, redirect.Header().Get("Location"))
	}
}

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
