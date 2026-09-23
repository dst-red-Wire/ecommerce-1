package outbox

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

type fakeStore struct {
	events      []Event
	published   []string
	rescheduled []string
	deadLetters []string
}

func (s *fakeStore) Claim(context.Context, time.Time, time.Time, int, int) ([]Event, error) {
	return append([]Event(nil), s.events...), nil
}
func (s *fakeStore) MarkPublished(_ context.Context, id string, _ time.Time) error {
	s.published = append(s.published, id)
	return nil
}
func (s *fakeStore) Reschedule(_ context.Context, id string, _ time.Time, _ string) error {
	s.rescheduled = append(s.rescheduled, id)
	return nil
}
func (s *fakeStore) MoveToDeadLetter(_ context.Context, id string, _ string) error {
	s.deadLetters = append(s.deadLetters, id)
	return nil
}

type fakePublisher struct{ err error }

func (p fakePublisher) Publish(context.Context, string, []byte) error { return p.err }

func TestWorkerPublishesAndAcknowledges(t *testing.T) {
	store := &fakeStore{events: []Event{{ID: "event-1", Type: "product.ProductCreated.v1", AggregateID: "product-1", Payload: []byte{1}, AttemptCount: 1}}}
	worker := newTestWorker(t, store, fakePublisher{})
	if err := worker.ProcessOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.published) != 1 || len(store.rescheduled) != 0 || len(store.deadLetters) != 0 {
		t.Fatalf("unexpected state: %+v", store)
	}
}

func TestWorkerUsesBoundedRetryAndDeadLetter(t *testing.T) {
	store := &fakeStore{events: []Event{{ID: "event-1", Type: "product.ProductCreated.v1", Payload: []byte{1}, AttemptCount: 3}}}
	worker := newTestWorker(t, store, fakePublisher{err: errors.New("broker unavailable")})
	if err := worker.ProcessOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.rescheduled) != 0 || len(store.deadLetters) != 1 || len(store.published) != 0 {
		t.Fatalf("unexpected state: %+v", store)
	}
}

func newTestWorker(t *testing.T, store Store, publisher Publisher) *Worker {
	t.Helper()
	worker, err := NewWorker(store, publisher, slog.New(slog.NewJSONHandler(io.Discard, nil)), Options{
		BatchSize: 10, MaxAttempts: 3, PollInterval: time.Second, Lease: time.Second,
		RetryBase: time.Second, RetryMax: time.Minute, PublishLimit: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return worker
}
