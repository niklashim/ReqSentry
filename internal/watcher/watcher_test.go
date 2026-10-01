package watcher

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
	"github.com/niklashim/ReqSentry/internal/storage"
)

func testLine(ip, path string) string {
	return fmt.Sprintf("%s - - [01/Oct/2026:12:00:00 +0200] \"GET %s HTTP/1.1\" 200 10 \"-\" \"test\"\n", ip, path)
}

func appendText(t *testing.T, path, value string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.WriteString(value); err != nil {
		t.Fatal(err)
	}
}

func waitUntil(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition was not met before timeout")
}

func TestMultipleSitesPartialLinesRotationAndTruncation(t *testing.T) {
	dir := t.TempDir()
	one := filepath.Join(dir, "one.log")
	two := filepath.Join(dir, "two.log")
	for _, path := range []string{one, two} {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var logs bytes.Buffer
	events := make(chan model.RequestEvent, 16)
	manager := New([]config.AccessFile{{Path: one, Site: "one"}, {Path: two, Site: "two"}}, log.New(&logs, "", 0), func(event model.RequestEvent) { events <- event })
	manager.poll = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { manager.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	waitUntil(t, func() bool {
		status := manager.Status()
		return status[0].Open && status[1].Open
	})
	first := testLine("192.0.2.1", "/first")
	appendText(t, one, first[:len(first)-1])
	time.Sleep(30 * time.Millisecond)
	if len(events) != 0 {
		t.Fatal("partial line was emitted")
	}
	appendText(t, one, "\n")
	appendText(t, two, testLine("2001:db8::2", "/second"))
	waitUntil(t, func() bool { return len(events) == 2 })
	if err := os.Rename(one, one+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(one, []byte(testLine("192.0.2.3", "/new")), 0o600); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, func() bool { return len(events) == 3 })
	appendText(t, one+".1", testLine("192.0.2.4", "/old-late"))
	waitUntil(t, func() bool { return len(events) == 4 })
	if err := os.Truncate(two, 0); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	appendText(t, two, testLine("2001:db8::5", "/after-truncate"))
	waitUntil(t, func() bool { return len(events) == 5 })
	seen := map[string]string{}
	for len(events) > 0 {
		event := <-events
		seen[event.Path] = event.SiteID
	}
	for path, site := range map[string]string{"/first": "one", "/second": "two", "/new": "one", "/old-late": "one", "/after-truncate": "two"} {
		if seen[path] != site {
			t.Fatalf("event %s associated with %q, want %q; all=%v", path, seen[path], site, seen)
		}
	}
	status := manager.Status()
	if status[0].Parsed != 3 || status[1].Parsed != 2 || status[0].BadLines != 0 || status[1].BadLines != 0 {
		t.Fatalf("unexpected watcher status: %+v", status)
	}
}

func TestMissingFileRecoveryAndBoundedBadLineLogs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "later.log")
	var logs bytes.Buffer
	events := make(chan model.RequestEvent, 4)
	manager := New([]config.AccessFile{{Path: path, Site: "later"}}, log.New(&logs, "", 0), func(event model.RequestEvent) { events <- event })
	manager.poll = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { manager.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	waitUntil(t, func() bool { return manager.Status()[0].IOErrors > 0 })
	if err := os.WriteFile(path, []byte(testLine("192.0.2.10", "/appeared")), 0o600); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, func() bool { return len(events) == 1 && manager.Status()[0].Open })
	appendText(t, path, strings.Repeat("malformed\n", 16)+testLine("192.0.2.11", "/after-bad"))
	waitUntil(t, func() bool { return len(events) == 2 && manager.Status()[0].BadLines == 16 })
	cancel()
	<-done
	if got := strings.Count(logs.String(), "skipped malformed access log"); got != 5 {
		t.Fatalf("expected five sampled parse errors, got %d: %s", got, logs.String())
	}
	if manager.Status()[0].LastError != "" {
		t.Fatalf("recovered watcher retained error: %+v", manager.Status()[0])
	}
}

func TestRestartDoesNotReplayExistingLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "restart.log")
	if err := os.WriteFile(path, []byte(testLine("192.0.2.1", "/before-start")), 0o600); err != nil {
		t.Fatal(err)
	}
	for run := 0; run < 2; run++ {
		events := make(chan model.RequestEvent, 4)
		manager := New([]config.AccessFile{{Path: path, Site: "restart"}}, log.New(os.Stderr, "", 0), func(event model.RequestEvent) { events <- event })
		manager.poll = 10 * time.Millisecond
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { manager.Run(ctx); close(done) }()
		waitUntil(t, func() bool { return manager.Status()[0].Open })
		if len(events) != 0 {
			t.Fatalf("run %d replayed existing data", run)
		}
		appendText(t, path, testLine("192.0.2.2", fmt.Sprintf("/run-%d", run)))
		waitUntil(t, func() bool { return len(events) == 1 })
		cancel()
		<-done
	}
}

func TestCleanRestartReadsEntriesWrittenWhileStopped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "restart.log")
	if err := os.WriteFile(path, []byte(testLine("192.0.2.1", "/history")), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(filepath.Join(dir, "state.db"), os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var logs bytes.Buffer
	firstEvents := make(chan model.RequestEvent, 4)
	first := New([]config.AccessFile{{Path: path, Site: "shop"}}, log.New(&logs, "", 0), func(event model.RequestEvent) { firstEvents <- event })
	first.SetCheckpointStore(store)
	first.sources[0].step()
	if len(firstEvents) != 0 {
		t.Fatal("initial historical lines replayed")
	}
	appendText(t, path, testLine("192.0.2.2", "/during-run"))
	first.sources[0].step()
	if len(firstEvents) != 1 {
		t.Fatal("live entry missed")
	}
	first.sources[0].closeAll()
	first.CommitOffsets()
	appendText(t, path, testLine("2001:db8::3", "/while-stopped"))
	secondEvents := make(chan model.RequestEvent, 4)
	second := New([]config.AccessFile{{Path: path, Site: "shop"}}, log.New(&logs, "", 0), func(event model.RequestEvent) { secondEvents <- event })
	second.SetCheckpointStore(store)
	second.sources[0].step()
	defer second.sources[0].closeAll()
	if len(secondEvents) != 1 || (<-secondEvents).Path != "/while-stopped" {
		t.Fatal("clean restart did not resume at committed offset")
	}
}

func TestCrashReplaysFromLastCheckpoint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "crash.log")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(filepath.Join(dir, "state.db"), os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var logs bytes.Buffer
	first := New([]config.AccessFile{{Path: path, Site: "shop"}}, log.New(&logs, "", 0), func(model.RequestEvent) {})
	first.SetCheckpointStore(store)
	first.sources[0].step()
	appendText(t, path, testLine("192.0.2.1", "/uncommitted"))
	first.sources[0].step()
	// Simulate process death: descriptors close without a clean checkpoint.
	_ = first.sources[0].active.file.Close()
	var replayed []model.RequestEvent
	second := New([]config.AccessFile{{Path: path, Site: "shop"}}, log.New(&logs, "", 0), func(event model.RequestEvent) { replayed = append(replayed, event) })
	second.SetCheckpointStore(store)
	second.sources[0].step()
	defer second.sources[0].closeAll()
	if len(replayed) != 1 || replayed[0].Path != "/uncommitted" {
		t.Fatalf("crash window not replayed: %+v", replayed)
	}
}
