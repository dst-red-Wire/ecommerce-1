package outbox

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"
)

type Event struct {
	ID            string
	Type          string
	AggregateID   string
	Payload       []byte
	AttemptCount  int
	SchemaVersion int
}

type Store interface {
	Claim(context.Context, time.Time, time.Time, int, int) ([]Event, error)
	MarkPublished(context.Context, string, time.Time) error
	Reschedule(context.Context, string, time.Time, string) error
	MoveToDeadLetter(context.Context, string, string) error
}

type Publisher interface {
	Publish(context.Context, string, []byte) error
}

type Options struct {
	BatchSize    int
	MaxAttempts  int
	PollInterval time.Duration
	Lease        time.Duration
	RetryBase    time.Duration
	RetryMax     time.Duration
	PublishLimit time.Duration
}

type Worker struct {
	store     Store
	publisher Publisher
	logger    *slog.Logger
	options   Options
	now       func() time.Time
}

func NewWorker(store Store, publisher Publisher, logger *slog.Logger, options Options) (*Worker, error) {
	if store == nil || publisher == nil || logger == nil {
		return nil, errors.New("outbox worker dependencies are required")
	}
	if options.BatchSize < 1 || options.BatchSize > 100 || options.MaxAttempts < 1 ||
		options.PollInterval <= 0 || options.Lease <= 0 || options.RetryBase <= 0 ||
		options.RetryMax < options.RetryBase || options.PublishLimit <= 0 {
		return nil, errors.New("invalid outbox worker options")
	}
	return &Worker{store: store, publisher: publisher, logger: logger, options: options, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (w *Worker) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.options.PollInterval)
	defer ticker.Stop()
	for {
		if err := w.ProcessOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
			w.logger.ErrorContext(ctx, "outbox poll failed", "error", safeError(err))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (w *Worker) ProcessOnce(ctx context.Context) error {
	now := w.now()
	events, err := w.store.Claim(ctx, now, now.Add(w.options.Lease), w.options.BatchSize, w.options.MaxAttempts)
	if err != nil {
		return err
	}
	for _, event := range events {
		if event.AttemptCount > w.options.MaxAttempts {
			if err := w.store.MoveToDeadLetter(ctx, event.ID, "publisher lease expired after retry budget was exhausted"); err != nil {
				return err
			}
			continue
		}
		publishCtx, cancel := context.WithTimeout(ctx, w.options.PublishLimit)
		err := w.publisher.Publish(publishCtx, event.AggregateID, event.Payload)
		cancel()
		if err == nil {
			if err := w.store.MarkPublished(ctx, event.ID, w.now()); err != nil {
				return err
			}
			w.logger.InfoContext(ctx, "outbox event published", "event_id", event.ID, "event_type", event.Type, "attempt", event.AttemptCount)
			continue
		}

		failure := safeError(err)
		if event.AttemptCount >= w.options.MaxAttempts {
			if deadLetterErr := w.store.MoveToDeadLetter(ctx, event.ID, failure); deadLetterErr != nil {
				return deadLetterErr
			}
			w.logger.ErrorContext(ctx, "outbox event exhausted retries", "event_id", event.ID, "event_type", event.Type, "attempt", event.AttemptCount)
			continue
		}

		next := w.now().Add(w.retryDelay(event.AttemptCount))
		if err := w.store.Reschedule(ctx, event.ID, next, failure); err != nil {
			return err
		}
		w.logger.WarnContext(ctx, "outbox event rescheduled", "event_id", event.ID, "event_type", event.Type, "attempt", event.AttemptCount)
	}
	return nil
}

func (w *Worker) retryDelay(attempt int) time.Duration {
	delay := w.options.RetryBase
	for i := 1; i < attempt && delay < w.options.RetryMax; i++ {
		if delay > w.options.RetryMax/2 {
			return w.options.RetryMax
		}
		delay *= 2
	}
	if delay > w.options.RetryMax {
		return w.options.RetryMax
	}
	return delay
}

func safeError(err error) string {
	message := strings.NewReplacer("\n", " ", "\r", " ", "\t", " ").Replace(err.Error())
	if len(message) > 512 {
		message = message[:512]
	}
	return message
}
