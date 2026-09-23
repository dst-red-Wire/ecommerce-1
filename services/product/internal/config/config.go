package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/outbox"
)

type Config struct {
	HTTPAddr          string
	GRPCAddr          string
	Storage           string
	DatabaseURL       string
	HomeSite          string
	OIDCIssuer        string
	OIDCAudience      string
	KafkaBrokers      []string
	KafkaTopic        string
	KafkaClientID     string
	KafkaTLSCAFile    string
	KafkaTLSCertFile  string
	KafkaTLSKeyFile   string
	KafkaMaxRetries   int
	KafkaDeliveryTime time.Duration
	ShutdownTimeout   time.Duration
	Outbox            outbox.Options
}

func Load() (Config, error) {
	config := Config{
		HTTPAddr: get("PRODUCT_HTTP_ADDR", ":8080"), GRPCAddr: get("PRODUCT_GRPC_ADDR", ":9090"),
		Storage: get("PRODUCT_STORAGE", "postgres"), DatabaseURL: strings.TrimSpace(os.Getenv("PRODUCT_DATABASE_URL")),
		HomeSite: strings.TrimSpace(os.Getenv("PRODUCT_HOME_SITE")), KafkaBrokers: csv(os.Getenv("PRODUCT_KAFKA_BROKERS")),
		OIDCIssuer: strings.TrimSpace(os.Getenv("PRODUCT_OIDC_ISSUER")), OIDCAudience: strings.TrimSpace(os.Getenv("PRODUCT_OIDC_AUDIENCE")),
		KafkaTopic: get("PRODUCT_KAFKA_TOPIC", "ecommerce.product.events.v1"), KafkaClientID: get("PRODUCT_KAFKA_CLIENT_ID", "product"),
		KafkaTLSCAFile:   strings.TrimSpace(os.Getenv("PRODUCT_KAFKA_TLS_CA_FILE")),
		KafkaTLSCertFile: strings.TrimSpace(os.Getenv("PRODUCT_KAFKA_TLS_CERT_FILE")),
		KafkaTLSKeyFile:  strings.TrimSpace(os.Getenv("PRODUCT_KAFKA_TLS_KEY_FILE")),
	}
	var err error
	if config.KafkaMaxRetries, err = integer("PRODUCT_KAFKA_MAX_RETRIES", 2); err != nil {
		return Config{}, err
	}
	if config.KafkaDeliveryTime, err = duration("PRODUCT_KAFKA_DELIVERY_TIMEOUT", 10*time.Second); err != nil {
		return Config{}, err
	}
	if config.ShutdownTimeout, err = duration("PRODUCT_SHUTDOWN_TIMEOUT", 10*time.Second); err != nil {
		return Config{}, err
	}
	if config.Outbox.BatchSize, err = integer("PRODUCT_OUTBOX_BATCH_SIZE", 50); err != nil {
		return Config{}, err
	}
	if config.Outbox.MaxAttempts, err = integer("PRODUCT_OUTBOX_MAX_ATTEMPTS", 5); err != nil {
		return Config{}, err
	}
	if config.Outbox.PollInterval, err = duration("PRODUCT_OUTBOX_POLL_INTERVAL", time.Second); err != nil {
		return Config{}, err
	}
	if config.Outbox.Lease, err = duration("PRODUCT_OUTBOX_LEASE", 30*time.Second); err != nil {
		return Config{}, err
	}
	if config.Outbox.RetryBase, err = duration("PRODUCT_OUTBOX_RETRY_BASE", time.Second); err != nil {
		return Config{}, err
	}
	if config.Outbox.RetryMax, err = duration("PRODUCT_OUTBOX_RETRY_MAX", time.Minute); err != nil {
		return Config{}, err
	}
	if config.Outbox.PublishLimit, err = duration("PRODUCT_OUTBOX_PUBLISH_TIMEOUT", 10*time.Second); err != nil {
		return Config{}, err
	}
	if err := config.validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (c Config) validate() error {
	if c.Storage != "memory" && c.Storage != "postgres" {
		return fmt.Errorf("unsupported PRODUCT_STORAGE %q", c.Storage)
	}
	if c.Storage == "postgres" {
		missing := make([]string, 0, 5)
		if c.DatabaseURL == "" {
			missing = append(missing, "PRODUCT_DATABASE_URL")
		}
		if len(c.KafkaBrokers) == 0 {
			missing = append(missing, "PRODUCT_KAFKA_BROKERS")
		}
		if c.HomeSite == "" {
			missing = append(missing, "PRODUCT_HOME_SITE")
		}
		if c.OIDCIssuer == "" {
			missing = append(missing, "PRODUCT_OIDC_ISSUER")
		}
		if c.OIDCAudience == "" {
			missing = append(missing, "PRODUCT_OIDC_AUDIENCE")
		}
		if c.KafkaTLSCAFile == "" {
			missing = append(missing, "PRODUCT_KAFKA_TLS_CA_FILE")
		}
		if c.KafkaTLSCertFile == "" {
			missing = append(missing, "PRODUCT_KAFKA_TLS_CERT_FILE")
		}
		if c.KafkaTLSKeyFile == "" {
			missing = append(missing, "PRODUCT_KAFKA_TLS_KEY_FILE")
		}
		if len(missing) > 0 {
			return fmt.Errorf("required PostgreSQL runtime configuration missing: %s", strings.Join(missing, ", "))
		}
	}
	if c.KafkaMaxRetries < 0 || c.ShutdownTimeout <= 0 {
		return errors.New("runtime retry and timeout values must be positive")
	}
	return nil
}

func get(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func csv(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			result = append(result, part)
		}
	}
	return result
}

func integer(name string, fallback int) (int, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer: %w", name, err)
	}
	return parsed, nil
}

func duration(name string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be a duration: %w", name, err)
	}
	return parsed, nil
}
