package rest

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/application"
	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/domain"
	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/infrastructure/memory"
)

func newTestHandler() http.Handler {
	store := memory.NewStore()
	return NewHandler(application.NewService(store, store))
}

func request(t *testing.T, h http.Handler, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(payload))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func authHeaders() map[string]string {
	return map[string]string{"Authorization": "Bearer local-test-token"}
}

func TestHealthDoesNotRequireBearer(t *testing.T) {
	rec := request(t, newTestHandler(), http.MethodGet, "/healthz", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestBusinessRouteRequiresBearer(t *testing.T) {
	rec := request(t, newTestHandler(), http.MethodGet, "/v1/products", nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Fatalf("expected problem+json, got %q", got)
	}
}

func TestProductLifecycleAndIdempotency(t *testing.T) {
	h := newTestHandler()
	headers := authHeaders()
	headers["Idempotency-Key"] = "product-create-0001"
	body := map[string]any{"name": "Lampe NOMA", "status": "active", "attributes": map[string]any{"material": "metal"}}

	created := request(t, h, http.MethodPost, "/v1/products", body, headers)
	if created.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", created.Code, created.Body.String())
	}
	var product domain.Product
	if err := json.Unmarshal(created.Body.Bytes(), &product); err != nil {
		t.Fatal(err)
	}
	if product.ID == "" || product.Version != 1 || product.Status != domain.ProductStatusActive {
		t.Fatalf("unexpected product: %+v", product)
	}
	etag := created.Header().Get("ETag")
	if etag != "\"v1\"" {
		t.Fatalf("unexpected ETag %q", etag)
	}

	replayed := request(t, h, http.MethodPost, "/v1/products", body, headers)
	if replayed.Code != http.StatusCreated {
		t.Fatalf("expected replay 201, got %d", replayed.Code)
	}
	var replayedProduct domain.Product
	if err := json.Unmarshal(replayed.Body.Bytes(), &replayedProduct); err != nil {
		t.Fatal(err)
	}
	if replayedProduct.ID != product.ID || replayedProduct.Version != product.Version {
		t.Fatalf("idempotency replay changed result: %+v vs %+v", replayedProduct, product)
	}

	conflicting := map[string]string{"Authorization": "Bearer local-test-token", "Idempotency-Key": "product-create-0001"}
	conflict := request(t, h, http.MethodPost, "/v1/products", map[string]any{"name": "Different"}, conflicting)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("expected 409 for idempotency conflict, got %d: %s", conflict.Code, conflict.Body.String())
	}

	get := request(t, h, http.MethodGet, "/v1/products/"+product.ID, nil, authHeaders())
	if get.Code != http.StatusOK || get.Header().Get("ETag") != etag {
		t.Fatalf("get failed: code=%d etag=%q body=%s", get.Code, get.Header().Get("ETag"), get.Body.String())
	}

	patchHeaders := authHeaders()
	patchHeaders["Idempotency-Key"] = "product-update-0001"
	patchHeaders["If-Match"] = "\"v99\""
	precondition := request(t, h, http.MethodPatch, "/v1/products/"+product.ID, map[string]any{"brand": "NOMA"}, patchHeaders)
	if precondition.Code != http.StatusPreconditionFailed {
		t.Fatalf("expected 412, got %d: %s", precondition.Code, precondition.Body.String())
	}

	patchHeaders["If-Match"] = etag
	updated := request(t, h, http.MethodPatch, "/v1/products/"+product.ID, map[string]any{"brand": "NOMA"}, patchHeaders)
	if updated.Code != http.StatusOK || updated.Header().Get("ETag") != "\"v2\"" {
		t.Fatalf("patch failed: code=%d etag=%q body=%s", updated.Code, updated.Header().Get("ETag"), updated.Body.String())
	}
}

func TestSKULifecycle(t *testing.T) {
	h := newTestHandler()
	productHeaders := authHeaders()
	productHeaders["Idempotency-Key"] = "product-create-sku-parent"
	created := request(t, h, http.MethodPost, "/v1/products", map[string]any{"name": "Chaise"}, productHeaders)
	if created.Code != http.StatusCreated {
		t.Fatalf("product create failed: %d %s", created.Code, created.Body.String())
	}
	var product domain.Product
	if err := json.Unmarshal(created.Body.Bytes(), &product); err != nil {
		t.Fatal(err)
	}

	skuHeaders := authHeaders()
	skuHeaders["Idempotency-Key"] = "sku-create-0001"
	skuBody := map[string]any{"code": "CHAIR-BLK", "gtin": "12345678", "optionValues": map[string]string{"color": "black"}}
	skuCreated := request(t, h, http.MethodPost, "/v1/products/"+product.ID+"/skus", skuBody, skuHeaders)
	if skuCreated.Code != http.StatusCreated {
		t.Fatalf("sku create failed: %d %s", skuCreated.Code, skuCreated.Body.String())
	}
	var sku domain.SKU
	if err := json.Unmarshal(skuCreated.Body.Bytes(), &sku); err != nil {
		t.Fatal(err)
	}
	if sku.ProductID != product.ID || sku.Code != "CHAIR-BLK" || sku.Version != 1 {
		t.Fatalf("unexpected sku: %+v", sku)
	}

	list := request(t, h, http.MethodGet, "/v1/products/"+product.ID+"/skus?limit=1", nil, authHeaders())
	if list.Code != http.StatusOK {
		t.Fatalf("sku list failed: %d %s", list.Code, list.Body.String())
	}

	patchHeaders := authHeaders()
	patchHeaders["Idempotency-Key"] = "sku-update-0001"
	patchHeaders["If-Match"] = skuCreated.Header().Get("ETag")
	updated := request(t, h, http.MethodPatch, "/v1/products/"+product.ID+"/skus/"+sku.ID, map[string]any{"status": "inactive"}, patchHeaders)
	if updated.Code != http.StatusOK || updated.Header().Get("ETag") != "\"v2\"" {
		t.Fatalf("sku patch failed: code=%d etag=%q body=%s", updated.Code, updated.Header().Get("ETag"), updated.Body.String())
	}
}

func TestUnknownFieldsFailClosed(t *testing.T) {
	h := newTestHandler()
	headers := authHeaders()
	headers["Idempotency-Key"] = "product-create-extra"
	rec := request(t, h, http.MethodPost, "/v1/products", map[string]any{"name": "Valid", "price": 10}, headers)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unowned/unknown field, got %d: %s", rec.Code, rec.Body.String())
	}
}
