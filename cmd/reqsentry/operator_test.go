package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/daemon"
	"github.com/niklashim/ReqSentry/internal/model"
	"github.com/niklashim/ReqSentry/internal/storage"
)

func operatorFixture(t *testing.T) (config.Config, string) {
	t.Helper()
	dir := t.TempDir()
	input := filepath.Join(dir, "access.log")
	os.WriteFile(input, []byte("source log"), 0600)
	path := filepath.Join(dir, "config.yaml")
	text := "# retain this operator note\nserver:\n  name: test\naccess_files:\n  - path: " + input + "\n    site: shop.example\ndatabase:\n  path: " + filepath.Join(dir, "history.db") + "\noutput:\n  log:\n    enabled: true\n    path: " + filepath.Join(dir, "output.log") + "\n  incidents:\n    enabled: true\n    path: " + filepath.Join(dir, "incidents.jsonl") + "\n"
	if err := os.WriteFile(path, []byte(text), 0640); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(cfg.Database.Path, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return cfg, path
}
func invoke(t *testing.T, path string, args ...string) (int, string, string) {
	t.Helper()
	var out, diagnostics bytes.Buffer
	code := run(append([]string{"-config", path}, args...), &out, &diagnostics)
	return code, out.String(), diagnostics.String()
}
func TestReportFiltersBeforeLimitAndPreservesJSON(t *testing.T) {
	cfg, path := operatorFixture(t)
	store, err := storage.Open(cfg.Database.Path, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	target := mockIncident()
	target.Timestamp = now
	target.Signals = []model.Signal{{Code: "PATH_ENUMERATION", Weight: 40, Strength: model.SignalStrong}}
	target.RequestSamples = []model.RequestSample{{Timestamp: now, Method: "GET", Path: "/test\x1b[2J", Status: 404}}
	other := target
	other.ClientIP = netip.MustParseAddr("192.0.2.2")
	other.SiteID = "other.example"
	other.RequestSamples = nil
	expired := target
	expired.Timestamp = now.Add(-5 * 24 * time.Hour)
	for _, i := range []model.Incident{expired, target, other} {
		if err := store.WriteIncident(context.Background(), i); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	code, out, diagnostics := invoke(t, path, "-limit", "1", "-ip", target.ClientIP.String(), "-site", target.SiteID, "-details", "report")
	if code != 0 || !strings.Contains(out, "WOULD_BLOCK") || !strings.Contains(out, "weight=40") || !strings.Contains(out, "/test [2J") || strings.Contains(out, "\x1b") || strings.Contains(out, "192.0.2.2") {
		t.Fatalf("code=%d out=%s err=%s", code, out, diagnostics)
	}
	code, out, diagnostics = invoke(t, path, "-json", "report")
	var list []model.Incident
	if err := json.Unmarshal([]byte(out), &list); code != 0 || err != nil || len(list) != 2 {
		t.Fatalf("JSON code=%d list=%v err=%v diagnostics=%s", code, list, err, diagnostics)
	}
	for _, args := range [][]string{{"-ip", "invalid", "report"}, {"-limit", "0", "report"}, {"-limit", "1001", "report"}} {
		code, _, _ := invoke(t, path, args...)
		if code != 2 {
			t.Fatalf("invalid filter accepted: %v", args)
		}
	}
	code, out, _ = invoke(t, path, "-site", "absent", "report")
	if code != 0 || !strings.Contains(out, "No retained findings") {
		t.Fatal(out)
	}
}
func TestHumanStatusAndReplay(t *testing.T) {
	cfg, path := operatorFixture(t)
	code, out, err := invoke(t, path, "status")
	if code != 0 || !strings.Contains(out, "heartbeat unavailable") || strings.Contains(out, "\"running\"") {
		t.Fatalf("%d %s %s", code, out, err)
	}
	os.WriteFile(cfg.AccessFiles[0].Path, []byte("192.0.2.1 - - [04/Oct/2026:12:00:00 +0000] \"GET / HTTP/1.1\" 200 12 \"-\" \"Mozilla\"\n"), 0600)
	code, out, err = invoke(t, path, "replay", cfg.AccessFiles[0].Path)
	if code != 0 || !strings.Contains(out, "Parsed: 1") || !strings.Contains(out, "MONITOR ONLY") {
		t.Fatalf("%d %s %s", code, out, err)
	}
	var help bytes.Buffer
	if code := run([]string{"-help"}, io.Discard, &help); code != 0 || !strings.Contains(help.String(), "data clean") {
		t.Fatal(code, help.String())
	}
}
func TestUITogglePreservesCommentedReferenceAndAccessPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	example, err := os.ReadFile("../../configs/example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, example, 0640)
	if err := saveUI(path, true); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil || !cfg.Web.Enabled || cfg.Web.Listen != "127.0.0.1" || len(cfg.Web.AllowedIPs) != 2 {
		t.Fatalf("%+v %v", cfg.Web, err)
	}
	data, _ := os.ReadFile(path)
	for _, marker := range []string{"PHP configuration reference", "#   password_env:", "#   interval:", "#   enabled: true"} {
		if !strings.Contains(string(data), marker) {
			t.Fatalf("comment lost: %s", marker)
		}
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0640 {
		t.Fatal(info.Mode())
	}
	if err := saveUI(path, false); err != nil {
		t.Fatal(err)
	}
	cfg, err = config.Load(path)
	if err != nil || cfg.Web.Enabled || len(cfg.Web.AllowedIPs) != 2 {
		t.Fatalf("%+v %v", cfg.Web, err)
	}
	// Existing explicit access restrictions survive both toggles.
	text := strings.Replace(string(data), "127.0.0.1\n    - ::1", "192.0.2.1\n    - ::1", 1)
	os.WriteFile(path, []byte(text), 0640)
	if err := saveUI(path, false); err != nil {
		t.Fatal(err)
	}
	cfg, _ = config.Load(path)
	if cfg.Web.AllowedIPs[0] != "192.0.2.1" {
		t.Fatalf("policy changed: %v; %s", cfg.Web.AllowedIPs, text)
	}
	link := filepath.Join(dir, "link.yaml")
	os.Symlink(path, link)
	if err := saveUI(link, true); err == nil {
		t.Fatal("rewrote symlink")
	}
}
func TestCleanupConfirmLockAndScope(t *testing.T) {
	cfg, path := operatorFixture(t)
	dir := filepath.Dir(path)
	for _, p := range []string{cfg.Output.Log.Path, cfg.Output.Incidents.Path, cfg.Output.Log.Path + ".reqsentry.1.2.3.archive", cfg.Output.Incidents.Path + ".reqsentry.1.2.quarantine"} {
		os.WriteFile(p, []byte("private output"), 0600)
	}
	preserved := []string{path, cfg.AccessFiles[0].Path, filepath.Join(dir, "GeoLite2-Country.mmdb"), cfg.Output.Log.Path + ".reqsentry.do-not-delete.archive"}
	for _, p := range preserved[2:] {
		os.WriteFile(p, []byte("preserve"), 0600)
	}
	code, _, _ := invoke(t, path, "data", "clean")
	if code != 2 {
		t.Fatal("cleanup did not require confirmation")
	}
	code, out, diagnostics := invoke(t, path, "data", "preview")
	if code != 0 || !strings.Contains(out, "Would remove:") || !strings.Contains(out, "quarantine") {
		t.Fatalf("%d %s %s", code, out, diagnostics)
	}
	guard, err := dataGuard(cfg.Database.Path, false)
	if err != nil {
		t.Fatal(err)
	}
	code, _, diagnostics = invoke(t, path, "-confirm", "data", "clean")
	if code != 1 || !strings.Contains(diagnostics, "data is in use") {
		t.Fatal(code, diagnostics)
	}
	guard.Close()
	code, out, diagnostics = invoke(t, path, "-confirm", "data", "clean")
	if code != 0 {
		t.Fatalf("%d %s %s", code, out, diagnostics)
	}
	for _, p := range preserved {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("protected file removed: %s: %v", p, err)
		}
	}
	for _, p := range []string{cfg.Database.Path, cfg.Output.Log.Path, cfg.Output.Incidents.Path, cfg.Output.Log.Path + ".reqsentry.1.2.3.archive", cfg.Output.Incidents.Path + ".reqsentry.1.2.quarantine"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("data remains: %s", p)
		}
	}
	code, _, diagnostics = invoke(t, path, "-confirm", "data", "clean")
	if code != 0 {
		t.Fatal("repeated cleanup failed", diagnostics)
	}
}
func TestCleanupRejectsFreshLegacyDaemonAndProtectedTargets(t *testing.T) {
	cfg, path := operatorFixture(t)
	store, err := storage.Open(cfg.Database.Path, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	status, _ := json.Marshal(daemon.Status{UpdatedAt: time.Now().UTC(), Running: true})
	store.SetState(context.Background(), "daemon.status", string(status))
	store.Close()
	code, _, diagnostics := invoke(t, path, "-confirm", "data", "clean")
	if code != 1 || !strings.Contains(diagnostics, "heartbeat") {
		t.Fatal(code, diagnostics)
	}
	cfg.Output.Log.Path = cfg.AccessFiles[0].Path
	if _, err := dataFiles(cfg, path); err == nil {
		t.Fatal("source collision allowed")
	}
	cfg.Output.Log.Path = filepath.Join(filepath.Dir(path), "linked.log")
	os.Link(cfg.AccessFiles[0].Path, cfg.Output.Log.Path)
	if _, err := dataFiles(cfg, path); err == nil {
		t.Fatal("hardlink collision allowed")
	}
	os.Remove(cfg.Output.Log.Path)
	os.Symlink(cfg.AccessFiles[0].Path, cfg.Output.Log.Path)
	if _, err := dataFiles(cfg, path); err == nil {
		t.Fatal("symlink deletion allowed")
	}
}

type fakeTransport func(*http.Request) (*http.Response, error)

func (f fakeTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestLegacySlackTestAndOfflinePreview(t *testing.T) {
	_, path := operatorFixture(t)
	data, _ := os.ReadFile(path)
	data = append(data, []byte("  slack:\n    enabled: true\n    webhook_env: REQSENTRY_TEST_SLACK\n")...)
	os.WriteFile(path, data, 0640)
	t.Setenv("REQSENTRY_TEST_SLACK", "https://hooks.slack.com/services/TEST/ONLY/FAKE")
	original := http.DefaultTransport
	defer func() { http.DefaultTransport = original }()
	calls := 0
	http.DefaultTransport = fakeTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "SYNTHETIC TEST") || r.URL.Host != "hooks.slack.com" {
			t.Fatalf("unexpected fake request: %s %s", r.URL, body)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})
	for _, args := range [][]string{{"notifications", "test", "legacy-slack"}, {"notifications", "test"}} {
		code, out, err := invoke(t, path, args...)
		if code != 0 || !strings.Contains(out, "accepted") {
			t.Fatalf("%d %s %s", code, out, err)
		}
	}
	code, out, err := invoke(t, path, "notifications", "preview")
	if code != 0 || !strings.Contains(out, "MOCK SLACK") || !strings.Contains(out, "ip=203.0.113.31") || calls != 2 {
		t.Fatalf("%d %s %s calls=%d", code, out, err, calls)
	}
	http.DefaultTransport = fakeTransport(func(*http.Request) (*http.Response, error) { return nil, errors.New("fake provider failure") })
	code, _, _ = invoke(t, path, "notifications", "test")
	if code != 1 {
		t.Fatal("provider failure ignored")
	}
}

func TestHeadlessEngineReportsAndKeepsFileOutputWithoutSQLite(t *testing.T) {
	for _, degraded := range []bool{false, true} {
		t.Run(fmt.Sprintf("sqlite_unavailable_%t", degraded), func(t *testing.T) {
			cfg, path := operatorFixture(t)
			os.WriteFile(cfg.AccessFiles[0].Path, nil, 0600)
			data, _ := os.ReadFile(path)
			text := strings.Replace(string(data), "    site: shop.example", "    site: shop.example\n    format: json", 1) + "analysis:\n  window: 2s\n"
			if degraded {
				notDir := filepath.Join(filepath.Dir(path), "not-a-directory")
				os.WriteFile(notDir, []byte("fixture"), 0600)
				text = strings.Replace(text, cfg.Database.Path, filepath.Join(notDir, "state.db"), 1)
			}
			os.WriteFile(path, []byte(text), 0640)
			var diagnostics crashTestLog
			child := exec.Command(os.Args[0], "-test.run=^TestCrashHelper$")
			child.Env = append(os.Environ(), "REQSENTRY_TEST_CRASH_CONFIG="+path)
			child.Stderr = &diagnostics
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			t.Cleanup(func() {
				if !waited {
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
					time.Sleep(25 * time.Millisecond)
				}
				t.Fatalf("%s: %s", stage, diagnostics.String())
			}
			wait("watcher ready", func() bool { return strings.Contains(diagnostics.String(), "watching log source path=") })
			if !degraded {
				code, out, err := invoke(t, path, "-json", "status")
				var state daemon.Status
				if code != 0 || json.Unmarshal([]byte(out), &state) != nil || !state.Running || state.Web.Enabled {
					t.Fatalf("headless status: %d %s %s", code, out, err)
				}
				code, _, err = invoke(t, path, "-confirm", "data", "clean")
				if code != 1 || !strings.Contains(err, "data is in use") {
					t.Fatal("cleanup allowed live engine", code, err)
				}
			} else if !strings.Contains(diagnostics.String(), "SQLite unavailable") {
				t.Fatal(diagnostics.String())
			}
			var lines bytes.Buffer
			at := time.Now().UTC().Format(time.RFC3339Nano)
			for j := 0; j < 600; j++ {
				fmt.Fprintf(&lines, `{"timestamp":%q,"client_ip":"203.0.113.31","method":"POST","path":"/scan/%d","status":404}`+"\n", at, j)
			}
			file, err := os.OpenFile(cfg.AccessFiles[0].Path, os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = file.Write(lines.Bytes()); err != nil {
				t.Fatal(err)
			}
			file.Close()
			wait("file incident", func() bool {
				output, err := os.ReadFile(cfg.Output.Incidents.Path)
				return err == nil && bytes.Contains(output, []byte("WOULD_BLOCK"))
			})
			if !degraded {
				wait("CLI report", func() bool {
					code, out, _ := invoke(t, path, "-ip", "203.0.113.31", "report")
					return code == 0 && strings.Contains(out, "WOULD_BLOCK") && strings.Contains(out, "shop.example")
				})
			}
			if err := child.Process.Signal(os.Interrupt); err != nil {
				t.Fatal(err)
			}
			err = child.Wait()
			waited = true
			if err != nil {
				t.Fatalf("shutdown: %v %s", err, diagnostics.String())
			}
		})
	}
}

func TestNotificationSelectionAndOutputLock(t *testing.T) {
	cfg, path := operatorFixture(t)
	code, _, err := invoke(t, path, "notifications", "test")
	if code != 1 || !strings.Contains(err, "no notification destinations") {
		t.Fatal(code, err)
	}
	data, _ := os.ReadFile(path)
	data = append(data, []byte("  destinations:\n    - name: alpha\n      type: slack\n      enabled: true\n      webhook_env: REQSENTRY_TEST_SLACK\n    - name: beta\n      type: slack\n      enabled: true\n      webhook_env: REQSENTRY_TEST_SLACK\n")...)
	os.WriteFile(path, data, 0640)
	code, _, err = invoke(t, path, "notifications", "test")
	if code != 2 || !strings.Contains(err, "multiple destinations") {
		t.Fatal(code, err)
	}
	// Output-only monitoring must also be protected when SQLite is unavailable.
	guard, lockErr := dataGuard(cfg.Output.Log.Path, false)
	if lockErr != nil {
		t.Fatal(lockErr)
	}
	defer guard.Close()
	code, _, err = invoke(t, path, "-confirm", "data", "clean")
	if code != 1 || !strings.Contains(err, "data is in use") {
		t.Fatal("output lock ignored", code, err)
	}
}
