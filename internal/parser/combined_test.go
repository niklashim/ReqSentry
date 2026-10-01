package parser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixtureLines(t *testing.T, name string) []string {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(contents)), "\n")
}

func TestNginxCombinedAndEnriched(t *testing.T) {
	lines := fixtureLines(t, "nginx.log")
	plain, err := Parse(lines[0], "shop")
	if err != nil {
		t.Fatal(err)
	}
	if plain.SiteID != "shop" || plain.ClientIP.String() != "192.0.2.10" || plain.Method != "GET" || plain.Path != "/products" || plain.Query != "id=42" || plain.Status != 404 {
		t.Fatalf("unexpected plain event: %+v", plain)
	}
	if plain.RequestTime != nil || plain.UpstreamTime != nil || plain.Referrer != nil || plain.Bytes == nil || *plain.Bytes != 123 {
		t.Fatalf("optional fields misrepresented: %+v", plain)
	}
	enriched, err := Parse(lines[1], "shop")
	if err != nil {
		t.Fatal(err)
	}
	if enriched.ClientIP.String() != "2001:db8::42" || enriched.Host != "shop.example.test" || enriched.Path != "/api/items" || enriched.Query != "q=a%20b" {
		t.Fatalf("unexpected enriched event: %+v", enriched)
	}
	if enriched.RequestTime == nil || *enriched.RequestTime != 123*time.Millisecond || enriched.UpstreamTime == nil || *enriched.UpstreamTime != 120*time.Millisecond {
		t.Fatalf("timing fields: %+v", enriched)
	}
	if enriched.Referrer == nil || *enriched.Referrer != "https://example.test/a\"b" || enriched.UserAgent == nil || *enriched.UserAgent != "client\\tool" {
		t.Fatalf("escaped fields: %+v", enriched)
	}
}

func TestApacheCombinedAndEnriched(t *testing.T) {
	lines := fixtureLines(t, "apache.log")
	plain, err := Parse(lines[0], "default")
	if err != nil {
		t.Fatal(err)
	}
	if plain.Bytes != nil || plain.Referrer != nil || plain.UserAgent == nil || *plain.UserAgent != "curl/8.0" {
		t.Fatalf("optional fields: %+v", plain)
	}
	enriched, err := Parse(lines[1], "shop")
	if err != nil {
		t.Fatal(err)
	}
	if enriched.ClientIP.String() != "2001:db8::5" || enriched.Host != "shop.example.test" || enriched.Method != "OPTIONS" || enriched.Path != "/api" || enriched.Query != "x=1" {
		t.Fatalf("unexpected Apache event: %+v", enriched)
	}
	if enriched.RequestTime == nil || *enriched.RequestTime != 2500*time.Microsecond || enriched.UpstreamTime != nil {
		t.Fatalf("Apache timing: %+v", enriched)
	}
	if enriched.UserAgent == nil || *enriched.UserAgent != "api-client\"test" {
		t.Fatalf("Apache escaped User-Agent: %+v", enriched)
	}
}

func TestLongURLAndMissingOptionalFields(t *testing.T) {
	path := "/" + strings.Repeat("a", 8192)
	line := `203.0.113.1 - - [01/Oct/2026:12:00:04 +0200] "GET ` + path + ` HTTP/1.1" 200 -`
	event, err := Parse(line, "long")
	if err != nil {
		t.Fatal(err)
	}
	if event.Method != "GET" || event.Path != path || event.Bytes != nil || event.UserAgent != nil || event.RequestTime != nil {
		t.Fatalf("long URL or optional fields: %+v", event)
	}
}

func TestProxyEvidence(t *testing.T) {
	line := `10.0.0.2 - - [01/Oct/2026:12:00:00 +0200] "GET / HTTP/1.1" 200 0 "-" "-" peer="10.0.0.2" xff="203.0.113.9, 10.0.0.1"`
	event, err := Parse(line, "shop")
	if err != nil {
		t.Fatal(err)
	}
	if event.LogIP.String() != "10.0.0.2" || event.PeerIP.String() != "10.0.0.2" || event.ForwardedFor != "203.0.113.9, 10.0.0.1" {
		t.Fatalf("proxy fields: %+v", event)
	}
}

func TestRejectsMalformedLines(t *testing.T) {
	valid := fixtureLines(t, "nginx.log")[0]
	tests := []string{
		"not a log",
		strings.Replace(valid, "192.0.2.10", "not-an-ip", 1),
		strings.Replace(valid, " 404 123 ", " xx 123 ", 1),
		strings.Replace(valid, "id=42", "id=%zz", 1),
		strings.Replace(valid, "Mozilla/5.0", `bad\q`, 1),
		strings.TrimSuffix(valid, `"Mozilla/5.0"`) + `"unterminated`,
	}
	for _, line := range tests {
		if _, err := Parse(line, "shop"); err == nil {
			t.Fatalf("expected parse error for %q", line)
		}
	}
}

func TestOptionalRedirectLocation(t *testing.T) {
	line := `192.0.2.1 - - [01/Oct/2026:12:00:00 +0200] "GET /old HTTP/1.1" 301 0 "-" "test" loc="/new?id=12"`
	event, err := Parse(line, "shop")
	if err != nil || event.Location == nil || *event.Location != "/new?id=12" {
		t.Fatalf("Location not parsed: %+v %v", event, err)
	}
}
