package rest

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func BenchmarkListProductsEmpty(b *testing.B) {
	handler := newTestHandler()
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		req := httptest.NewRequest(http.MethodGet, "/v1/products", nil)
		req.Header.Set("Authorization", "Bearer local-benchmark-token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("expected 200, got %d", rec.Code)
		}
	}
}
