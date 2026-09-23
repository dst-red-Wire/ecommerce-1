package kafka

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

type Producer struct {
	client *kgo.Client
	topic  string
}

type Config struct {
	Brokers         []string
	Topic           string
	ClientID        string
	MaxRetries      int
	DeliveryTimeout time.Duration
	TLSCAFile       string
	TLSCertFile     string
	TLSKeyFile      string
}

func New(config Config) (*Producer, error) {
	if len(config.Brokers) == 0 || strings.TrimSpace(config.Topic) == "" || strings.TrimSpace(config.ClientID) == "" {
		return nil, errors.New("Kafka brokers, topic, and client ID are required")
	}
	if config.MaxRetries < 0 || config.DeliveryTimeout <= 0 {
		return nil, errors.New("Kafka retry and delivery settings are invalid")
	}
	tlsConfig, err := loadTLSConfig(config)
	if err != nil {
		return nil, err
	}
	client, err := kgo.NewClient(
		kgo.SeedBrokers(config.Brokers...),
		kgo.ClientID(config.ClientID),
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.RecordRetries(config.MaxRetries),
		kgo.RecordDeliveryTimeout(config.DeliveryTimeout),
		kgo.DialTLSConfig(tlsConfig),
	)
	if err != nil {
		return nil, err
	}
	return &Producer{client: client, topic: config.Topic}, nil
}

func loadTLSConfig(config Config) (*tls.Config, error) {
	if strings.TrimSpace(config.TLSCAFile) == "" || strings.TrimSpace(config.TLSCertFile) == "" || strings.TrimSpace(config.TLSKeyFile) == "" {
		return nil, errors.New("Kafka mTLS CA, certificate, and key files are required")
	}
	caPEM, err := os.ReadFile(config.TLSCAFile)
	if err != nil {
		return nil, fmt.Errorf("read Kafka TLS CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("Kafka TLS CA contains no valid certificates")
	}
	identity, err := tls.LoadX509KeyPair(config.TLSCertFile, config.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load Kafka TLS client identity: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      roots,
		Certificates: []tls.Certificate{identity},
	}, nil
}

func (p *Producer) Publish(ctx context.Context, aggregateID string, payload []byte) error {
	if len(payload) == 0 {
		return errors.New("Kafka payload is empty")
	}
	result := p.client.ProduceSync(ctx, &kgo.Record{Topic: p.topic, Key: []byte(aggregateID), Value: payload})
	return result.FirstErr()
}

func (p *Producer) Ping(ctx context.Context) error { return p.client.Ping(ctx) }

func (p *Producer) Close() { p.client.Close() }
