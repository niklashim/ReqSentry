package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/niklashim/ReqSentry/internal/storage"
)

func TestCrashHelper(t *testing.T) {
	if path := os.Getenv("REQSENTRY_TEST_CRASH_CONFIG"); path != "" {
		os.Exit(run([]string{"-config", path}, io.Discard, os.Stderr))
	}
}

type crashTestLog struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (b *crashTestLog) Write(v []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.Write(v)
}
func (b *crashTestLog) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.data.String() }
func TestProcessCrashPreservesOpenWindow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.jsonl")
	db := filepath.Join(dir, "state.db")
	os.WriteFile(path, nil, 0600)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	configPath := filepath.Join(dir, "config.yaml")
	cfg := fmt.Sprintf("server:\n  name: crash-test\naccess_files:\n  - path: %s\n    site: shop\n    format: json\ndatabase:\n  path: %s\nrecovery:\n  enabled: true\n  interval: 1s\nweb:\n  enabled: true\n  port: %d\n  allowed_ips: [127.0.0.1]\n", path, db, port)
	os.WriteFile(configPath, []byte(cfg), 0600)
	client := &http.Client{Timeout: time.Second}
	url := fmt.Sprintf("http://127.0.0.1:%d/api/v1/stats", port)
	var diagnostics crashTestLog
	start := func() *exec.Cmd {
		cmd := exec.Command(os.Args[0], "-test.run=^TestCrashHelper$")
		cmd.Env = append(os.Environ(), "REQSENTRY_TEST_CRASH_CONFIG="+configPath)
		cmd.Stderr = &diagnostics
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		return cmd
	}
	child := start()
	t.Cleanup(func() {
		if child.Process != nil {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	})
	wait := func(stage string, condition func() bool) {
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			if condition() {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("daemon condition timed out (%s):\n%s", stage, diagnostics.String())
	}
	requests := func() uint64 {
		resp, err := client.Get(url)
		if err != nil {
			return 0
		}
		defer resp.Body.Close()
		var data struct {
			Live struct {
				Requests uint64 `json:"requests"`
			} `json:"live"`
		}
		if json.NewDecoder(resp.Body).Decode(&data) != nil {
			return 0
		}
		return data.Live.Requests
	}
	wait("initial HTTP listener", func() bool {
		resp, err := client.Get(url)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == 200
	})
	// HTTP can be ready before the watcher captures its initial EOF position.
	// Append only after that capture so this test exercises new live requests.
	wait("initial watcher ready", func() bool { return strings.Contains(diagnostics.String(), "watching log source path="+path+" ") })
	// Do not cross a 30-second boundary while exercising the unfinished window.
	if time.Until(time.Now().Truncate(30*time.Second).Add(30*time.Second)) < 3*time.Second {
		time.Sleep(3 * time.Second)
	}
	at := time.Now().UTC()
	write := func(first, last int) {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		enc := json.NewEncoder(f)
		for j := first; j < last; j++ {
			if err := enc.Encode(map[string]any{"timestamp": at, "client_ip": "192.0.2.1", "method": "GET", "path": fmt.Sprintf("/scan/%d", j), "status": 404}); err != nil {
				t.Fatal(err)
			}
		}
	}
	write(0, 150)
	wait("initial 150 requests", func() bool { return requests() == 150 })
	time.Sleep(1100 * time.Millisecond)
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	write(150, 300)
	child = start()
	wait("first restart 300 requests", func() bool { return requests() == 300 })
	// The recovery path remains idempotent across another unclean shutdown.
	_ = child.Process.Kill()
	_ = child.Wait()
	child = start()
	wait("second restart 300 requests", func() bool { return requests() == 300 })
	_ = child.Process.Kill()
	_ = child.Wait()
	child.Process = nil
	s, err := storage.Open(db, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, found, err := s.LoadOffset(context.Background(), path); err != nil || !found {
		t.Fatal("checkpoint missing", err)
	}
}
