package domain

import "testing"

func TestStatusWireValues(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"product draft", string(ProductStatusDraft), "draft"},
		{"product active", string(ProductStatusActive), "active"},
		{"product archived", string(ProductStatusArchived), "archived"},
		{"sku active", string(SKUStatusActive), "active"},
		{"sku inactive", string(SKUStatusInactive), "inactive"},
		{"sku archived", string(SKUStatusArchived), "archived"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("wire value = %q, want %q", tt.got, tt.want)
			}
		})
	}
}
