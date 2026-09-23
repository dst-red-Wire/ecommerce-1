package main

import (
	"context"
	"sync"
	"testing"
	"time"
)

type blockingGRPCStopper struct {
	mu      sync.Mutex
	forced  bool
	release chan struct{}
}

func (s *blockingGRPCStopper) GracefulStop() { <-s.release }
func (s *blockingGRPCStopper) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.forced {
		s.forced = true
		close(s.release)
	}
}

func TestStopGRPCForcesStopAtDeadline(t *testing.T) {
	server := &blockingGRPCStopper{release: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	stopGRPC(ctx, server)
	server.mu.Lock()
	defer server.mu.Unlock()
	if !server.forced {
		t.Fatal("expected forced gRPC stop after graceful shutdown deadline")
	}
}
