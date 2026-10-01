package replay

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
)

func logLine(ip string, at time.Time, method, path string, status int, extras string) string {
	return fmt.Sprintf("%s - - [%s] \"%s %s HTTP/1.1\" %d 12 \"-\" \"Mozilla/5.0\" %s\n", ip, at.Format("02/Jan/2006:15:04:05 -0700"), method, path, status, extras)
}

func TestReplayNormalAndScanningWindows(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shop.log")
	start := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	var lines strings.Builder
	for i := 0; i < 10; i++ {
		lines.WriteString(logLine("2001:db8::1", start.Add(time.Duration(i)*time.Second), "GET", "/", 200, ""))
		lines.WriteString(logLine("2001:db8::3", start.Add(time.Duration(i)*time.Second), "POST", "/api/items", 200, ""))
	}
	for i := 0; i < 40; i++ {
		lines.WriteString(logLine("2001:db8::2", start.Add(30*time.Second+time.Duration(i/2)*time.Second), "GET", fmt.Sprintf("/users/%d", i), 404, ""))
	}
	if err := os.WriteFile(path, []byte(lines.String()), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Server: config.ServerConfig{Name: "replay-test"}, Mode: "monitor", AccessFiles: []config.AccessFile{{Path: path, Site: "shop"}}, Database: config.DatabaseConfig{Path: filepath.Join(dir, "unused.db")}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	var incidents []model.Incident
	summary, err := Run(context.Background(), []string{path}, cfg, func(value model.Incident) error { incidents = append(incidents, value); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if summary.Parsed != 60 || summary.BadLines != 0 || summary.Incidents == 0 {
		t.Fatalf("summary=%+v", summary)
	}
	found := false
	for _, incident := range incidents {
		if incident.ClientIP.String() == "2001:db8::2" && incident.SiteID == "shop" {
			found = true
			if !incident.MonitorOnly || incident.Decision == model.DecisionNormal || incident.Requests != 40 {
				t.Fatalf("incident=%+v", incident)
			}
		}
	}
	if !found {
		t.Fatalf("scan missing: %+v", incidents)
	}
}

func TestReplayTrustedProxyAndAllowlist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "api.log")
	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	var lines strings.Builder
	for i := 0; i < 35; i++ {
		lines.WriteString(logLine("127.0.0.1", at, "GET", fmt.Sprintf("/missing/%d", i), 404, "peer=127.0.0.1 xff=2001:db8::7"))
	}
	if err := os.WriteFile(path, []byte(lines.String()), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Server: config.ServerConfig{Name: "test"}, AccessFiles: []config.AccessFile{{Path: path, Site: "api"}}, ClientIP: config.ClientIPConfig{TrustedProxies: []string{"127.0.0.1"}}, Database: config.DatabaseConfig{Path: filepath.Join(dir, "unused.db")}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	var seen bool
	_, err := Run(context.Background(), []string{path}, cfg, func(value model.Incident) error {
		if value.ClientIP.String() == "2001:db8::7" {
			seen = true
		}
		return nil
	})
	if err != nil || !seen {
		t.Fatalf("trusted proxy failed err=%v seen=%t", err, seen)
	}
	cfg.Allowlist = []string{"2001:db8::7"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	summary, err := Run(context.Background(), []string{path}, cfg, func(model.Incident) error { t.Fatal("allowlisted incident"); return nil })
	if err != nil || summary.Allowlisted != 35 || summary.Incidents != 0 {
		t.Fatalf("allowlist summary=%+v err=%v", summary, err)
	}
}

func TestReplayAdditionalBehaviorFixtures(t *testing.T) {
	start := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for _, scenario := range []struct {
		name       string
		files      map[string][]string
		watchScore int
		want       string
	}{
		{name: "query enumeration", watchScore: 10, want: "QUERY_ENUMERATION", files: func() map[string][]string {
			var lines []string
			for i := 0; i < 15; i++ {
				lines = append(lines, logLine("192.0.2.1", start.Add(time.Duration(i)*time.Second), "GET", fmt.Sprintf("/products?id=%d", i), 200, ""))
			}
			return map[string][]string{"shop": lines}
		}()},
		{name: "method scan", want: "METHOD_404_SCAN", files: func() map[string][]string {
			var lines []string
			for i := 0; i < 35; i++ {
				lines = append(lines, logLine("192.0.2.1", start.Add(time.Duration(i/2)*time.Second), "POST", fmt.Sprintf("/missing/%d", i), 404, ""))
			}
			return map[string][]string{"api": lines}
		}()},
		{name: "cross site scan", want: "CROSS_SITE_SCAN", files: func() map[string][]string {
			files := map[string][]string{}
			for site := 0; site < 3; site++ {
				name := fmt.Sprintf("site%d", site)
				for i := 0; i < 20; i++ {
					files[name] = append(files[name], logLine("192.0.2.1", start.Add(time.Duration(i)*time.Second), "GET", fmt.Sprintf("/missing/%d/%d", site, i), 404, ""))
				}
			}
			return files
		}()},
		{name: "low rate expensive requests", watchScore: 10, want: "HIGH_REQUEST_COST", files: func() map[string][]string {
			var lines []string
			for i := 0; i < 12; i++ {
				lines = append(lines, logLine("192.0.2.1", start.Add(time.Duration(i*2)*time.Second), "GET", "/slow", 200, "rt=\"0.900\""))
			}
			return map[string][]string{"app": lines}
		}()},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			dir := t.TempDir()
			var paths []string
			cfg := config.Config{Server: config.ServerConfig{Name: "replay"}, Database: config.DatabaseConfig{Path: filepath.Join(dir, "unused.db")}}
			for site, lines := range scenario.files {
				path := filepath.Join(dir, site+".log")
				if err := os.WriteFile(path, []byte(strings.Join(lines, "")), 0600); err != nil {
					t.Fatal(err)
				}
				paths = append(paths, path)
				cfg.AccessFiles = append(cfg.AccessFiles, config.AccessFile{Path: path, Site: site})
			}
			if err := cfg.Validate(); err != nil {
				t.Fatal(err)
			}
			if scenario.watchScore > 0 {
				cfg.Detection.WatchScore = scenario.watchScore
			}
			found := false
			_, err := Run(context.Background(), paths, cfg, func(incident model.Incident) error {
				for _, signal := range incident.Signals {
					if signal.Code == scenario.want {
						found = true
					}
				}
				return nil
			})
			if err != nil || !found {
				t.Fatalf("signal %s missing err=%v", scenario.want, err)
			}
		})
	}
}

func BenchmarkReplayAttackScale(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "attack.log")
	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	var lines strings.Builder
	for i := 0; i < 10000; i++ {
		lines.WriteString(logLine("192.0.2.1", at.Add(time.Duration(i/1000)*time.Second), "GET", fmt.Sprintf("/path/%d", i), 404, ""))
	}
	if err := os.WriteFile(path, []byte(lines.String()), 0600); err != nil {
		b.Fatal(err)
	}
	cfg := config.Config{Server: config.ServerConfig{Name: "bench"}, AccessFiles: []config.AccessFile{{Path: path, Site: "bench"}}, Database: config.DatabaseConfig{Path: filepath.Join(dir, "unused.db")}}
	if err := cfg.Validate(); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if summary, err := Run(context.Background(), []string{path}, cfg, func(model.Incident) error { return nil }); err != nil || summary.Dropped != 0 || summary.BadLines != 0 {
			b.Fatalf("replay summary=%+v err=%v", summary, err)
		}
	}
}

func BenchmarkReplayNormalScale(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "normal.log")
	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	var lines strings.Builder
	for i := 0; i < 1000; i++ {
		lines.WriteString(logLine(fmt.Sprintf("192.0.2.%d", i%100+1), at.Add(time.Duration(i/20)*time.Second), "GET", "/products", 200, ""))
	}
	if err := os.WriteFile(path, []byte(lines.String()), 0600); err != nil {
		b.Fatal(err)
	}
	cfg := config.Config{Server: config.ServerConfig{Name: "bench"}, AccessFiles: []config.AccessFile{{Path: path, Site: "bench"}}, Database: config.DatabaseConfig{Path: filepath.Join(dir, "unused.db")}}
	if err := cfg.Validate(); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if summary, err := Run(context.Background(), []string{path}, cfg, func(model.Incident) error { return nil }); err != nil || summary.Dropped != 0 || summary.BadLines != 0 {
			b.Fatalf("replay summary=%+v err=%v", summary, err)
		}
	}
}
