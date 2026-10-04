package watcher

import (
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
	"github.com/niklashim/ReqSentry/internal/storage"
)

func TestSafeCheckpointRetainsCompleteLineOverlap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "site.log")
	os.WriteFile(path, nil, 0600)
	store, err := storage.Open(filepath.Join(dir, "state.db"), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	count := 0
	m := New([]config.AccessFile{{Path: path, Site: "shop"}}, log.New(io.Discard, "", 0), func(model.RequestEvent) { count++ })
	m.SetCheckpointStore(store)
	m.sources[0].step()
	appendText(t, path, testLine("192.0.2.1", "/before"))
	m.sources[0].step()
	offsets, err := m.safeOffsets(time.Now(), time.Minute, 1<<20)
	if err != nil || offsets[path].Bytes != 0 {
		t.Fatalf("unfinished window skipped %+v %v", offsets, err)
	}
	if _, err := m.safeOffsets(time.Now(), time.Minute, 1); err == nil {
		t.Fatal("overlap budget ignored")
	}
	if err := store.SaveOffsets(context.Background(), offsets); err != nil {
		t.Fatal(err)
	}
	appendText(t, path, testLine("192.0.2.1", "/after"))
	m.sources[0].closeAll()
	recovered := 0
	next := New([]config.AccessFile{{Path: path, Site: "shop"}}, log.New(io.Discard, "", 0), func(model.RequestEvent) { recovered++ })
	next.SetCheckpointStore(store)
	next.sources[0].step()
	next.sources[0].closeAll()
	if count != 1 || recovered != 2 {
		t.Fatalf("threshold-crossing evidence lost count=%d recovered=%d", count, recovered)
	}
}

func TestErrorFloodDoesNotDisplaceAccessAndSurvivesRotation(t *testing.T) {
	dir := t.TempDir()
	access, errors := filepath.Join(dir, "access.log"), filepath.Join(dir, "errors.jsonl")
	for _, path := range []string{access, errors} {
		if err := os.WriteFile(path, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	var requests, failures atomic.Uint64
	m := New([]config.AccessFile{{Path: access, Site: "shop"}, {Path: errors, Site: "shop", Kind: "error", Format: "json", MinimumSeverity: "warning"}}, log.New(io.Discard, "", 0), func(model.RequestEvent) { requests.Add(1) })
	errorPaused, resumeErrors := make(chan struct{}), make(chan struct{})
	var pauseOnce, resumeOnce sync.Once
	resume := func() { resumeOnce.Do(func() { close(resumeErrors) }) }
	m.SetErrorSink(func(model.ErrorEvent) {
		pauseOnce.Do(func() {
			close(errorPaused)
			<-resumeErrors
		})
		failures.Add(1)
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	t.Cleanup(func() { resume(); cancel(); <-done })
	wait := func(stage string, timeout time.Duration, condition func() bool) {
		t.Helper()
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			if condition() {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("%s timed out: requests=%d errors=%d sources=%+v", stage, requests.Load(), failures.Load(), m.Status())
	}
	wait("sources open", 10*time.Second, func() bool { statuses := m.Status(); return statuses[0].Open && statuses[1].Open })
	line := `{"timestamp":"2026-10-03T12:00:00Z","severity":"error","message":"upstream timeout"}` + "\n"
	appendText(t, errors, strings.Repeat(line, 20000))
	// Establish a real backlog before writing access traffic. Holding the error
	// callback proves source isolation independently of machine/parser speed.
	wait("error callback paused", 10*time.Second, func() bool {
		select {
		case <-errorPaused:
			return true
		default:
			return false
		}
	})
	start := time.Now()
	appendText(t, access, strings.Repeat(testLine("192.0.2.1", "/"), 1000))
	wait("access traffic during paused error flood", 10*time.Second, func() bool { return requests.Load() == 1000 })
	t.Logf("1000 access lines under 20000-error flood: %s; errors observed at completion=%d", time.Since(start), failures.Load())
	if failures.Load() != 0 {
		t.Fatal("error flood was not held while verifying access independence")
	}
	appendText(t, errors, `{"timestamp":"2026-10-03T12:00:00Z","severity":"info","message":"noise"}`+"\n"+"invalid\n")
	if err := os.Rename(errors, errors+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(errors, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	appendText(t, access, testLine("192.0.2.1", "/after-rotation"))
	wait("access traffic after rotation during paused error flood", 10*time.Second, func() bool { return requests.Load() == 1001 })
	resume()
	// Completion is a correctness check, not a three-second parser benchmark.
	// Race-instrumented parsing of 20,000 errors is slower on constrained runners.
	wait("complete old/replacement error files", 30*time.Second, func() bool {
		s := m.Status()[1]
		return failures.Load() == 20001 && s.Filtered == 1 && s.BadLines == 1
	})
}
