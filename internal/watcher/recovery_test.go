package watcher

import (
	"context"
	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
	"github.com/niklashim/ReqSentry/internal/storage"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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
	m.SetErrorSink(func(model.ErrorEvent) { failures.Add(1) })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	waitUntil(t, func() bool { statuses := m.Status(); return statuses[0].Open && statuses[1].Open })
	line := `{"timestamp":"2026-10-03T12:00:00Z","severity":"error","message":"upstream timeout"}` + "\n"
	appendText(t, errors, strings.Repeat(line, 20000))
	start := time.Now()
	appendText(t, access, strings.Repeat(testLine("192.0.2.1", "/"), 1000))
	waitUntil(t, func() bool { return requests.Load() == 1000 })
	t.Logf("1000 access lines under 20000-error flood: %s; errors observed at completion=%d", time.Since(start), failures.Load())
	waitUntil(t, func() bool { return failures.Load() == 20000 })
	appendText(t, errors, `{"timestamp":"2026-10-03T12:00:00Z","severity":"info","message":"noise"}`+"\n"+"invalid\n")
	waitUntil(t, func() bool { s := m.Status()[1]; return s.Filtered == 1 && s.BadLines == 1 })
	if err := os.Rename(errors, errors+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(errors, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, func() bool { return failures.Load() == 20001 })
	appendText(t, access, testLine("192.0.2.1", "/after-rotation"))
	waitUntil(t, func() bool { return requests.Load() == 1001 })
}
