package kafka

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestNewFailsClosedWithoutMutualTLSIdentity(t *testing.T) {
	_, err := New(Config{
		Brokers: []string{"kafka.invalid:9093"}, Topic: "ecommerce.product.events.v1",
		ClientID: "product", MaxRetries: 2, DeliveryTimeout: time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "mTLS") {
		t.Fatalf("expected missing mTLS identity to fail closed, got %v", err)
	}
}

func TestNewRejectsInvalidCABundle(t *testing.T) {
	ca := t.TempDir() + "/ca.crt"
	if err := os.WriteFile(ca, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := New(Config{
		Brokers: []string{"kafka.invalid:9093"}, Topic: "ecommerce.product.events.v1",
		ClientID: "product", MaxRetries: 2, DeliveryTimeout: time.Second,
		TLSCAFile: ca, TLSCertFile: ca, TLSKeyFile: ca,
	})
	if err == nil || !strings.Contains(err.Error(), "no valid certificates") {
		t.Fatalf("expected invalid CA bundle to be rejected, got %v", err)
	}
}
