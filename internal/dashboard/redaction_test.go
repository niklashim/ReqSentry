package dashboard

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
	"github.com/niklashim/ReqSentry/internal/output"
	"github.com/niklashim/ReqSentry/internal/parser"
)

func TestSecretMarkersCannotReachSavedOrLocalEvidence(t *testing.T) {
	s := apiFixture(t)
	source, err := parser.NewSource(config.AccessFile{Path: "application.jsonl", Site: "shop", Format: "json", RetainStackTrace: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	messages := []string{"Authorization: Bearer AUDIT_SECRET", "Cookie: session=AUDIT_SECRET; refresh=SECOND_SECRET", `{"password":"AUDIT_SECRET"}`}
	for _, message := range messages {
		data, _ := json.Marshal(map[string]any{"timestamp": time.Now().UTC().Format(time.RFC3339Nano), "severity": "error", "message": message, "stack_trace": message})
		event, err := source.ParseError(string(data))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.store.WriteError(event); err != nil {
			t.Fatal(err)
		}
		incident := model.Incident{Timestamp: time.Now(), Errors: &model.ErrorContext{Samples: []model.ErrorMatch{{Event: event}}}}
		if err := s.store.WriteIncident(context.Background(), incident); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "incidents.jsonl")
		file := output.NewRetainedFile(path, io.Discard, 96*time.Hour, "incidents")
		if err := (output.IncidentFile{File: file}).WriteIncident(context.Background(), incident); err != nil {
			t.Fatal(err)
		}
		file.Close()
		value, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(value), "AUDIT_SECRET") || strings.Contains(string(value), "SECOND_SECRET") {
			t.Fatalf("local evidence leaked: %s", value)
		}
	}
	if err := s.store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/errors?site=shop&range=1h", "/api/v1/incidents"} {
		w := get(t, s, path)
		if w.Code != 200 || strings.Contains(w.Body.String(), "AUDIT_SECRET") || strings.Contains(w.Body.String(), "SECOND_SECRET") {
			t.Fatalf("API leaked: %d %s", w.Code, w.Body.String())
		}
	}
}
