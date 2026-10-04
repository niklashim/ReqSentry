package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/niklashim/ReqSentry/internal/model"
)

func TestFailedWritesSurviveUnrelatedFlushAndRetry(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	original := Offset{Bytes: 42}
	if err := s.SaveOffsets(ctx, map[string]Offset{"access": original}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER fail_incident BEFORE INSERT ON incidents BEGIN SELECT RAISE(FAIL,'injected outage'); END`); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	incident := model.Incident{EventID: "stable-retry", Timestamp: now, WindowStart: now.Add(-time.Minute), WindowEnd: now, SiteID: "shop", ClientIP: netip.MustParseAddr("192.0.2.1")}
	if err := s.WriteIncident(ctx, incident); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := s.Flush(ctx); err == nil {
			t.Fatal("unresolved batch forgotten")
		}
		if err := s.SaveOffsets(ctx, map[string]Offset{"access": {Bytes: 9000}}); err == nil {
			t.Fatal("checkpoint crossed failed write")
		}
	}
	offset, _, err := s.LoadOffset(ctx, "access")
	if err != nil || offset != original {
		t.Fatalf("checkpoint=%+v %v", offset, err)
	}
	if _, err := s.db.Exec(`DROP TRIGGER fail_incident`); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	items, err := s.RecentIncidents(ctx, 10)
	if err != nil || len(items) != 1 || items[0].EventID != "stable-retry" {
		t.Fatalf("retry=%+v %v", items, err)
	}
	if err := s.SaveOffsets(ctx, map[string]Offset{"access": {Bytes: 9000}}); err != nil {
		t.Fatal(err)
	}
	// Overflow is a permanent loss barrier, even after other writes recover.
	s.markWriteLoss(ErrQueueFull)
	for range 3 {
		if err := s.Flush(ctx); err == nil {
			t.Fatal("queue rejection forgotten")
		}
	}
	if err := s.SaveOffsets(ctx, map[string]Offset{"access": {Bytes: 12000}}); err == nil {
		t.Fatal("checkpoint crossed queue loss")
	}
}

func TestOutageRestartPreservesReplayCheckpoint(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "restart.db")
	s, err := Open(path, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := Offset{Device: 1, Inode: 2, Bytes: 100}
	if err := s.SaveOffsets(ctx, map[string]Offset{"access": checkpoint}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER fail_incident BEFORE INSERT ON incidents BEGIN SELECT RAISE(FAIL,'outage'); END`); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	event := model.Incident{EventID: "replayed", Timestamp: now, WindowStart: now.Add(-time.Minute), WindowEnd: now, SiteID: "shop", ClientIP: netip.MustParseAddr("192.0.2.1")}
	s.WriteIncident(ctx, event)
	for range 3 {
		if err := s.Flush(ctx); err == nil {
			t.Fatal("outage hidden")
		}
	}
	if err := s.SaveOffsets(ctx, map[string]Offset{"access": {Bytes: 100000}}); err == nil {
		t.Fatal("outage checkpoint advanced")
	}
	if err := s.Close(); err == nil {
		t.Fatal("shutdown hid outstanding loss")
	}
	s, err = Open(path, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	offset, found, err := s.LoadOffset(ctx, "access")
	if err != nil || !found || offset != checkpoint {
		t.Fatalf("restart lost overlap: %+v %t %v", offset, found, err)
	}
	if _, err := s.db.Exec(`DROP TRIGGER fail_incident`); err != nil {
		t.Fatal(err)
	}
	// Input replay starts from the old offset and deduplicates the stable event.
	for range 2 {
		if err := s.WriteIncident(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	items, err := s.RecentIncidents(ctx, 10)
	if err != nil || len(items) != 1 || items[0].EventID != "replayed" {
		t.Fatalf("replay=%+v %v", items, err)
	}
}

func TestRetryBufferIsBoundedAndOverflowRemainsSticky(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "bounded.db"), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.db.Exec(`CREATE TRIGGER fail_incident BEFORE INSERT ON incidents BEGIN SELECT RAISE(FAIL,'outage'); END`); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for batch := range 6 {
		for i := range 64 {
			event := model.Incident{EventID: fmt.Sprintf("%d-%d", batch, i), Timestamp: now, SiteID: "shop", ClientIP: netip.MustParseAddr("192.0.2.1")}
			if err := s.WriteIncident(ctx, event); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.Flush(ctx); err == nil {
			t.Fatal("outage hidden")
		}
	}
	if _, err := s.db.Exec(`DROP TRIGGER fail_incident`); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := s.Flush(ctx); err == nil {
			t.Fatal("overflow loss was cleared by successful retries")
		}
	}
	items, err := s.RecentIncidents(ctx, 1000)
	if err != nil || len(items) != 320 {
		t.Fatalf("retry buffer was not bounded: %d %v", len(items), err)
	}
	if err := s.SaveOffsets(ctx, map[string]Offset{"access": {Bytes: 999999}}); err == nil {
		t.Fatal("overflow crossed checkpoint")
	}
}

func TestCheckpointDeadlineAndFullQueueBarrierDoNotBlockIngestion(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Exercise the real checkpoint/queue methods without a database worker:
		// the full queue cannot lose a slot between setup and the assertion.
		// Database commits and retries are covered by the integration tests above.
		s := &Store{queue: make(chan writeRequest, 256), durableGate: make(chan struct{}, 1)}
		if err := s.beginDurable(context.Background()); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		err := s.SaveOffsets(ctx, map[string]Offset{"access": {Bytes: 123}})
		cancel()
		s.endDurable()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("checkpoint ignored deadline: %v", err)
		}
		event := model.Incident{Timestamp: time.Now(), ClientIP: netip.MustParseAddr("192.0.2.1")}
		for range cap(s.queue) {
			if err := s.WriteIncident(context.Background(), event); err != nil {
				t.Fatalf("queue fill failed: %v", err)
			}
		}
		flushCtx, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer stop()
		done := make(chan error, 1)
		go func() { done <- s.Flush(flushCtx) }()
		// Wait until Flush is blocked sending its barrier, without guessing how
		// long the scheduler or race instrumentation takes to reach that point.
		synctest.Wait()
		if !s.mu.TryLock() {
			t.Fatal("barrier owns the ingestion mutex while waiting for a queue slot")
		}
		s.mu.Unlock()
		if err := s.WriteIncident(context.Background(), event); !errors.Is(err, ErrQueueFull) {
			t.Fatalf("unexpected full queue result: %v", err)
		}
		time.Sleep(100 * time.Millisecond) // Advances the synthetic clock only.
		synctest.Wait()
		if err := <-done; !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("flush ignored deadline: %v", err)
		}
	})
}
