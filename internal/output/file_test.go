package output

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/niklashim/ReqSentry/internal/model"
)

func TestIncidentJSONLAndRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "incidents.jsonl")
	var diagnostics bytes.Buffer
	file := NewFile(path, &diagnostics)
	sink := IncidentFile{File: file}
	first := model.Incident{
		Timestamp: time.Unix(100, 0).UTC(), Server: "web-a", SiteID: "shop",
		ClientIP: netip.MustParseAddr("2001:db8::1"), Score: 90,
		Decision: model.DecisionWouldBlock, RulesetVersion: 3, MonitorOnly: true,
		Signals: []model.Signal{{Code: "HIGH_404_DIVERSITY", Weight: 25, Evidence: map[string]any{"unique": 40}}},
	}
	if err := sink.WriteIncident(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	waitForContent(t, path, "2001:db8::1")
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	second := first
	second.ClientIP = netip.MustParseAddr("192.0.2.4")
	if err := sink.WriteIncident(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	file.Close()
	for _, target := range []string{path + ".1", path} {
		data, err := os.ReadFile(target)
		if err != nil {
			t.Fatal(err)
		}
		lines := bytes.Split(bytes.TrimSpace(data), []byte{'\n'})
		if len(lines) != 1 {
			t.Fatalf("expected one record in %s: %s", target, data)
		}
		var record map[string]any
		if err := json.Unmarshal(lines[0], &record); err != nil {
			t.Fatal(err)
		}
		if record["monitor_only"] != true || record["ruleset_version"] != float64(3) || record["decision"] != string(model.DecisionWouldBlock) {
			t.Fatalf("missing monitor decision fields: %#v", record)
		}
		if _, ok := record["signals"].([]any); !ok {
			t.Fatalf("missing signal evidence: %#v", record)
		}
	}
	if diagnostics.Len() != 0 {
		t.Fatalf("unexpected output errors: %s", diagnostics.String())
	}
}

func TestFailedDestinationDoesNotStopAnother(t *testing.T) {
	dir := t.TempDir()
	var diagnostics bytes.Buffer
	bad := NewFile(filepath.Join(dir, "absent", "bad.log"), &diagnostics)
	goodPath := filepath.Join(dir, "good.log")
	good := NewFile(goodPath, &diagnostics)
	_, _ = bad.Write([]byte("failed destination\n"))
	_, _ = good.Write([]byte("available destination\n"))
	bad.Close()
	good.Close()
	data, err := os.ReadFile(goodPath)
	if err != nil || string(data) != "available destination\n" {
		t.Fatalf("healthy destination failed: %q %v", data, err)
	}
	if !strings.Contains(diagnostics.String(), "output unavailable") {
		t.Fatalf("missing destination failure: %s", diagnostics.String())
	}
}

func waitForContent(t *testing.T, path, fragment string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil && strings.Contains(string(data), fragment) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q in %s", fragment, path)
}
