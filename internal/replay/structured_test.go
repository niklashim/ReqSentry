package replay

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMixedFormatsErrorCorrelationAndPreview(t *testing.T) {
	dir := t.TempDir()
	access := filepath.Join(dir, "access.jsonl")
	errors := filepath.Join(dir, "errors.jsonl")
	file, err := os.Create(access)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	encoder := json.NewEncoder(file)
	for j := 0; j < 300; j++ {
		if err := encoder.Encode(map[string]any{"timestamp": at, "client_ip": "192.0.2.1", "method": "GET", "path": fmt.Sprintf("/scan/%d", j), "status": 404, "request_id": "one"}); err != nil {
			t.Fatal(err)
		}
	}
	file.Close()
	if err := os.WriteFile(errors, []byte(`{"timestamp":"2026-10-03T12:00:01Z","severity":"error","message":"upstream timed out","request_id":"one"}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Server: config.ServerConfig{Name: "test"}, AccessFiles: []config.AccessFile{{Path: access, Site: "shop", Format: "json"}}, ErrorFiles: []config.AccessFile{{Path: errors, Site: "shop", Format: "json"}}, Database: config.DatabaseConfig{Path: filepath.Join(dir, "state.db")}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	var saved []model.Incident
	summary, err := Run(context.Background(), []string{access, errors}, cfg, func(i model.Incident) error { saved = append(saved, i); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if summary.Parsed != 300 || summary.ErrorEvents != 1 || len(saved) != 2 {
		t.Fatalf("bad summary: %+v saved=%d", summary, len(saved))
	}
	for _, i := range saved {
		if i.Errors == nil || i.Errors.Associations["request_id"] != 1 || i.Decision != model.DecisionWouldBlock {
			t.Fatalf("correlation/score: %+v", i)
		}
	}
	preview, err := PreviewSource(context.Background(), access, cfg, 10)
	if err != nil || preview.Parsed != 10 || len(preview.Samples) != 5 || preview.Missing["request_time"] != 10 {
		t.Fatalf("bad preview %+v %v", preview, err)
	}
	if _, err := os.Stat(cfg.Database.Path); !os.IsNotExist(err) {
		t.Fatal("preview or replay created database")
	}
}

func TestCombinedJSONLogfmtReplayDecisionsEquivalent(t *testing.T) {
	var baseline []model.Incident
	for _, format := range []string{"combined", "json", "logfmt"} {
		dir := t.TempDir()
		path := filepath.Join(dir, "access.log")
		var lines strings.Builder
		for j := 0; j < 300; j++ {
			switch format {
			case "combined":
				fmt.Fprintf(&lines, "192.0.2.1 - - [03/Oct/2026:12:00:00 +0000] \"GET /scan/%d HTTP/1.1\" 404 10 \"-\" \"agent\" rid=one\n", j)
			case "json":
				fmt.Fprintf(&lines, "{\"timestamp\":\"2026-10-03T12:00:00Z\",\"client_ip\":\"192.0.2.1\",\"method\":\"GET\",\"path\":\"/scan/%d\",\"status\":404,\"bytes\":10,\"user_agent\":\"agent\",\"request_id\":\"one\"}\n", j)
			case "logfmt":
				fmt.Fprintf(&lines, "timestamp=2026-10-03T12:00:00Z client_ip=192.0.2.1 method=GET path=/scan/%d status=404 bytes=10 user_agent=agent request_id=one\n", j)
			}
		}
		if err := os.WriteFile(path, []byte(lines.String()), 0600); err != nil {
			t.Fatal(err)
		}
		cfg := config.Config{Server: config.ServerConfig{Name: "test"}, AccessFiles: []config.AccessFile{{Path: path, Site: "shop", Format: format}}, Database: config.DatabaseConfig{Path: filepath.Join(dir, "state.db")}}
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		var saved []model.Incident
		summary, err := Run(context.Background(), []string{path}, cfg, func(i model.Incident) error { saved = append(saved, i); return nil })
		if err != nil || summary.Parsed != 300 || summary.BadLines != 0 || len(saved) != 2 {
			t.Fatalf("%s summary=%+v err=%v incidents=%d", format, summary, err, len(saved))
		}
		if baseline == nil {
			baseline = saved
			continue
		}
		for j, i := range saved {
			if i.Score != baseline[j].Score || i.Decision != baseline[j].Decision || i.Requests != baseline[j].Requests || i.EventID != baseline[j].EventID {
				t.Fatalf("%s changed decision: got=%+v want=%+v", format, i, baseline[j])
			}
		}
	}
}
func TestReplayRejectsOutOfOrderRecords(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.jsonl")
	if err := os.WriteFile(path, []byte(`{"timestamp":"2026-10-03T12:00:02Z","client_ip":"192.0.2.1","method":"GET","path":"/","status":200}`+"\n"+`{"timestamp":"2026-10-03T12:00:01Z","client_ip":"192.0.2.1","method":"GET","path":"/","status":200}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Server: config.ServerConfig{Name: "test"}, AccessFiles: []config.AccessFile{{Path: path, Site: "shop", Format: "json"}}, Database: config.DatabaseConfig{Path: filepath.Join(dir, "state.db")}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), []string{path}, cfg, func(model.Incident) error { return nil }); err == nil {
		t.Fatal("out-of-order source accepted")
	}
}
