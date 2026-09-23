package kafka

import (
	"context"
	"errors"
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
}

func New(config Config) (*Producer, error) {
	if len(config.Brokers) == 0 || strings.TrimSpace(config.Topic) == "" || strings.TrimSpace(config.ClientID) == "" {
		return nil, errors.New("Kafka brokers, topic, and client ID are required")
	}
	if config.MaxRetries < 0 || config.DeliveryTimeout <= 0 {
		return nil, errors.New("Kafka retry and delivery settings are invalid")
	}
	client, err := kgo.NewClient(
		kgo.SeedBrokers(config.Brokers...),
		kgo.ClientID(config.ClientID),
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.RecordRetries(config.MaxRetries),
		kgo.RecordDeliveryTimeout(config.DeliveryTimeout),
	)
	if err != nil {
		return nil, err
	}
	return &Producer{client: client, topic: config.Topic}, nil
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
