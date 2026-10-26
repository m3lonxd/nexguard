package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestPusherRetriesUntilSuccess(t *testing.T) {
	p := newPusher()
	var attempts int32
	p.push(func() error {
		n := atomic.AddInt32(&attempts, 1)
		if n < 3 {
			return errors.New("panel unreachable")
		}
		return nil
	})

	if atomic.LoadInt32(&attempts) != 1 {
		t.Fatalf("expected exactly 1 attempt synchronously, got %d", attempts)
	}

	p.flush()
	if atomic.LoadInt32(&attempts) != 2 {
		t.Fatalf("expected 2 attempts after first flush, got %d", attempts)
	}

	p.flush()
	if atomic.LoadInt32(&attempts) != 3 {
		t.Fatalf("expected 3 attempts after second flush, got %d", attempts)
	}

	p.mu.Lock()
	remaining := len(p.pending)
	p.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("expected no pending items once the push succeeds, got %d", remaining)
	}
}

func TestPusherRetryLoopStopsOnContextCancel(t *testing.T) {
	p := newPusher()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		p.retryLoop(ctx, 5*time.Millisecond)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("retryLoop did not stop after context cancellation")
	}
}
