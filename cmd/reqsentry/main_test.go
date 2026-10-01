package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/niklashim/ReqSentry/internal/daemon"
	"github.com/niklashim/ReqSentry/internal/storage"
)

func TestOperatorCommands(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "state.db")
	logPath := filepath.Join(dir, "site.log")
	if err := os.WriteFile(logPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	yaml := "server:\n  name: test\nmode: monitor\naccess_files:\n  - path: " + logPath + "\n    site: test\ndatabase:\n  path: " + db + "\n"
	if err := os.WriteFile(configPath, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(db, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	status := daemon.Status{UpdatedAt: time.Now().UTC(), Running: true, SQLite: "available", MaxMind: "disabled", Slack: "disabled"}
	payload, _ := json.Marshal(status)
	if err := store.SetState(context.Background(), "daemon.status", string(payload)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	for _, testcase := range []struct {
		args []string
		want string
	}{
		{[]string{"-config", configPath, "config", "test"}, "configuration valid"},
		{[]string{"-config", configPath, "status"}, "\"running\": true"},
		{[]string{"-config", configPath, "report"}, "[]"},
		{[]string{"-config", configPath, "replay", logPath}, "\"summary\""},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(testcase.args, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), testcase.want) {
			t.Fatalf("args=%v code=%d stdout=%s stderr=%s", testcase.args, code, stdout.String(), stderr.String())
		}
	}
}
