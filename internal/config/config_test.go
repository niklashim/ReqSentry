package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const minimalConfig = `
server:
  name: test-server
access_files:
  - /var/log/nginx/site1.access.log
database:
  path: /var/lib/reqsentry/reqsentry.db
`

func loadText(t *testing.T, contents string) (Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func TestLoadExampleAndDefaults(t *testing.T) {
	cfg, err := Load("../../configs/example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "monitor" || cfg.Trigger.Mode != "always" || len(cfg.AccessFiles) != 1 {
		t.Fatalf("unexpected example config: %+v", cfg)
	}
	if cfg.Analysis.Window.Duration != 30*time.Second {
		t.Fatalf("unexpected analysis window: %s", cfg.Analysis.Window.Duration)
	}
	if cfg.AccessFiles[0].Site != "site1" || cfg.AccessFiles[0].Format != "combined" {
		t.Fatalf("unexpected access file mapping: %+v", cfg.AccessFiles)
	}
	if cfg.Database.Retention.MaxAge.Duration != 96*time.Hour {
		t.Fatalf("example should retain the shared four-day default: %+v", cfg.Database.Retention)
	}
	if cfg.Web.Enabled || cfg.MaxMind.Enabled || cfg.PHPFPM.Enabled || cfg.Recovery.Enabled ||
		cfg.Output.Log.Enabled || cfg.Output.Incidents.Enabled || cfg.Output.Slack.Enabled || len(cfg.Output.Destinations) != 0 {
		t.Fatal("commented reference should leave optional integrations disabled")
	}

	cfg, err = loadText(t, minimalConfig)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "monitor" || cfg.Trigger.Mode != "always" || cfg.AccessFiles[0].Site != "site1" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		{"enforcement", minimalConfig + "mode: enforce\n", "mode must be monitor"},
		{"unknown field", minimalConfig + "mdoe: monitor\n", "mdoe"},
		{"unknown access field", strings.Replace(minimalConfig, "  - /var/log/nginx/site1.access.log", "  - path: /var/log/nginx/site1.access.log\n    wrong: value", 1), "unknown access file field"},
		{"relative path", strings.Replace(minimalConfig, "/var/log/nginx/site1.access.log", "site1.access.log", 1), "clean absolute path"},
		{"duplicate path", strings.Replace(minimalConfig, "  - /var/log/nginx/site1.access.log", "  - /var/log/nginx/site1.access.log\n  - /var/log/nginx/site1.access.log", 1), "duplicate access file"},
		{"bad CPU thresholds", minimalConfig + "trigger:\n  mode: cpu\n  cpu_start: 60\n  cpu_stop: 80\n  start_duration: 10s\n  stop_duration: 60s\n", "CPU thresholds"},
		{"plaintext secret", minimalConfig + "maxmind:\n  enabled: true\n  license_key: literal-secret\n", "license_key"},
		{"extra document", minimalConfig + "---\nmode: monitor\n", "one YAML document"},
		{"invalid trusted proxy", minimalConfig + "client_ip:\n  trusted_proxies: [not-an-ip]\n", "client_ip.trusted_proxies"},
		{"trust all", minimalConfig + "client_ip:\n  trusted_proxies: [0.0.0.0/0]\n", "trust-all"},
		{"invalid allowlist", minimalConfig + "allowlist: [2001:db8::/999]\n", "allowlist"},
		{"analysis window too long", minimalConfig + "analysis:\n  window: 90s\n", "analysis.window"},
		{"invalid aggregation cap", minimalConfig + "aggregation:\n  max_active_records: -1\n", "aggregation.max_active_records"},
		{"invalid health interval", minimalConfig + "health:\n  interval: 100ms\n", "health.interval"},
		{"remote PHP-FPM URL", minimalConfig + "php_fpm:\n  enabled: true\n  pools:\n    - name: www\n      status_url: http://example.com/status\n", "loopback host"},
		{"unknown score weight", minimalConfig + "detection:\n  weights:\n    UNKNOWN: 50\n", "detection.weights.UNKNOWN"},
		{"invalid 404 ratio", minimalConfig + "detection:\n  thresholds:\n    high_404_ratio: 1.5\n", "high_404_ratio"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadText(t, tt.text)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestSecretReferences(t *testing.T) {
	for _, text := range []string{
		minimalConfig + "output:\n  slack:\n    enabled: true\n",
		minimalConfig + "output:\n  slack:\n    enabled: true\n    webhook_env: A\n    webhook_credential: B\n",
		minimalConfig + "output:\n  slack:\n    enabled: true\n    webhook_credential: ..\n",
	} {
		if _, err := loadText(t, text); err == nil {
			t.Fatalf("expected invalid secret reference for %q", text)
		}
	}
	t.Setenv("REQSENTRY_TEST_SECRET", "from-env")
	got, err := ResolveSecret("REQSENTRY_TEST_SECRET", "")
	if err != nil || got != "from-env" {
		t.Fatalf("environment reference: value=%q error=%v", got, err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "webhook"), []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	got, err = ResolveSecret("", "webhook")
	if err != nil || got != "from-file" {
		t.Fatalf("credential reference: value=%q error=%v", got, err)
	}
}

func TestWebDefaultsAndValidation(t *testing.T) {
	cfg, err := loadText(t, minimalConfig+"web:\n  enabled: true\n  allowed_ips: [127.0.0.1, '2001:db8::/48']\n")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Web.Listen != "127.0.0.1" || cfg.Web.Port != 8090 || cfg.Web.Realtime.Interval.Duration != 2*time.Second || cfg.Web.Realtime.Enabled == nil || !*cfg.Web.Realtime.Enabled {
		t.Fatalf("web defaults: %+v", cfg.Web)
	}
	for _, item := range []struct{ name, text, want string }{
		{"bad listen", "listen: example.com\n", "web.listen"},
		{"bad port", "port: 99999\n", "web.port"},
		{"bad allowed", "allowed_ips: [bad]\n", "web.allowed_ips"},
		{"trust all", "allowed_ips: [0.0.0.0/0]\n", "web.allowed_ips"},
		{"bad proxy", "trusted_proxies: [bad]\n", "web.trusted_proxies"},
		{"auth no secret", "auth:\n    enabled: true\n    username: admin\n", "web auth password"},
	} {
		t.Run(item.name, func(t *testing.T) {
			_, err := loadText(t, minimalConfig+"web:\n  enabled: true\n  "+item.text)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("expected %q, got %v", item.want, err)
			}
		})
	}
}
