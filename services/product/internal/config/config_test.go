package config

import "testing"

func TestMemoryConfigurationNeedsNoExternalSecrets(t *testing.T) {
	t.Setenv("PRODUCT_STORAGE", "memory")
	t.Setenv("PRODUCT_DATABASE_URL", "")
	t.Setenv("PRODUCT_KAFKA_BROKERS", "")
	t.Setenv("PRODUCT_HOME_SITE", "")
	t.Setenv("PRODUCT_OIDC_ISSUER", "")
	t.Setenv("PRODUCT_OIDC_AUDIENCE", "")
	config, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if config.Storage != "memory" || config.KafkaTopic != "ecommerce.product.events.v1" {
		t.Fatalf("unexpected config: %+v", config)
	}
}

func TestPostgresConfigurationFailsClosed(t *testing.T) {
	t.Setenv("PRODUCT_STORAGE", "postgres")
	t.Setenv("PRODUCT_DATABASE_URL", "")
	t.Setenv("PRODUCT_KAFKA_BROKERS", "")
	t.Setenv("PRODUCT_HOME_SITE", "")
	t.Setenv("PRODUCT_OIDC_ISSUER", "")
	t.Setenv("PRODUCT_OIDC_AUDIENCE", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected missing external configuration to fail")
	}
}
