package parser

import (
	"github.com/niklashim/ReqSentry/internal/clientidentity"
	"github.com/niklashim/ReqSentry/internal/config"
	"strings"
	"testing"
	"time"
)

func TestStructuredFormatsEquivalent(t *testing.T) {
	inputs := map[string]string{"json": `{"timestamp":"2026-10-03T12:00:00Z","client_ip":"2001:db8::1","method":"GET","path":"/users%2F1","query":"id=2","status":404,"bytes":0,"request_time":0,"request_id":"one"}`, "logfmt": `timestamp=2026-10-03T12:00:00Z client_ip=2001:db8::1 method=GET path=/users%2F1 query="id=2" status=404 bytes=0 request_time=0 request_id=one`}
	for format, line := range inputs {
		s, err := NewSource(config.AccessFile{Site: "shop", Format: format}, nil)
		if err != nil {
			t.Fatal(err)
		}
		e, err := s.Parse(line)
		if err != nil {
			t.Fatal(format, err)
		}
		if e.SiteID != "shop" || e.ClientIP.String() != "2001:db8::1" || e.Path != "/users%2F1" || e.Query != "id=2" || e.RequestTime == nil || *e.RequestTime != 0 || e.UpstreamTime != nil || e.Bytes == nil || e.RequestID != "one" {
			t.Fatalf("%s: %+v", format, e)
		}
	}
}
func TestNestedMappingAndUntrustedPeerEvidence(t *testing.T) {
	profiles := map[string]config.LogProfile{"app": {Fields: map[string]string{"timestamp": "/meta/time", "client_ip": "/remote/client", "peer": "/remote/peer", "xff": "/remote/xff", "method": "/http/method", "target": "/http/target", "status": "/http/status", "request_time": "elapsed.ms"}, DurationUnit: "ms"}}
	s, err := NewSource(config.AccessFile{Site: "configured", Format: "json", Profile: "app"}, profiles)
	if err != nil {
		t.Fatal(err)
	}
	e, err := s.Parse(`{"meta":{"time":"2026-10-03T12:00:00Z"},"remote":{"client":"192.0.2.99","peer":"192.0.2.1","xff":"192.0.2.3"},"http":{"method":"POST","target":"/api","status":"500"},"elapsed.ms":12,"host":"attacker"}`)
	if err != nil {
		t.Fatal(err)
	}
	if e.RequestTime == nil || *e.RequestTime != 12*time.Millisecond || e.SiteID != "configured" || e.PeerIP.String() != "192.0.2.1" {
		t.Fatalf("bad mapping: %+v", e)
	}
	for _, trusted := range []bool{false, true} {
		cfg := config.Config{}
		if trusted {
			cfg.ClientIP.TrustedProxies = []string{"192.0.2.1"}
		}
		resolver, err := clientidentity.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		resolved, _ := resolver.Resolve(e)
		want := "192.0.2.1"
		if trusted {
			want = "192.0.2.3"
		}
		if resolved.ClientIP.String() != want {
			t.Fatalf("trusted=%t resolved=%s", trusted, resolved.ClientIP)
		}
	}
}

func TestECSAccessAndPHPErrorSubset(t *testing.T) {
	profiles := map[string]config.LogProfile{"ecs": {Preset: "ecs-v1"}}
	s, err := NewSource(config.AccessFile{Site: "shop", Path: "php.jsonl", Format: "json", Profile: "ecs", RetainStackTrace: true}, profiles)
	if err != nil {
		t.Fatal(err)
	}
	line := `{"@timestamp":"2026-10-03T12:00:00Z","client":{"ip":"2001:db8::1"},"source":{"ip":"192.0.2.1"},"http":{"request":{"method":"GET","id":"req-1"},"response":{"status_code":500,"body":{"bytes":0}}},"url":{"path":"/api"},"event":{"duration":12000000},"trace":{"id":"trace-1"},"log":{"level":"fatal"},"error":{"type":"PHPException","code":"E42","message":"exception code 123 token=SECRET","stack_trace":"/var/www/private.php\npassword=HIDDEN"}}`
	r, err := s.Parse(line)
	if err != nil || r.RequestTime == nil || *r.RequestTime != 12*time.Millisecond || r.RequestID != "req-1" || r.PeerIP.String() != "192.0.2.1" {
		t.Fatalf("ECS request %+v %v", r, err)
	}
	e, err := s.ParseError(line)
	if err != nil || e.Category != "PHPException" || e.Severity != "critical" || e.TraceID != "trace-1" || !strings.HasPrefix(e.Fingerprint, "v1:") || strings.Contains(e.StackTrace, "private.php") || strings.Contains(e.StackTrace, "HIDDEN") || strings.Contains(e.Message, "SECRET") {
		t.Fatalf("ECS error %+v %v", e, err)
	}
	other, err := s.ParseError(strings.Replace(line, "code 123", "code 456", 1))
	if err != nil || other.Fingerprint != e.Fingerprint {
		t.Fatal("variable numeric values changed fingerprint", err)
	}
	s.File.RetainStackTrace = false
	e, err = s.ParseError(line)
	if err != nil || e.StackTrace != "" {
		t.Fatal("stack trace retained without opt in")
	}
}
func TestMalformedStructuredRecords(t *testing.T) {
	s, _ := NewSource(config.AccessFile{Site: "shop", Format: "json"}, nil)
	for _, line := range []string{`[]`, `{"status":200,"status":500}`, `{"timestamp":true}`, `{} {}`, strings.Repeat("[", 20) + strings.Repeat("]", 20), `{"timestamp":"2026-10-03T12:00:00Z","client_ip":"192.0.2.1","method":"GET","path":"/","status":200,"request_time":"NaN"}`} {
		if _, err := s.Parse(line); err == nil {
			t.Errorf("accepted invalid record %s", line)
		}
	}
	l, _ := NewSource(config.AccessFile{Site: "s", Format: "logfmt"}, nil)
	for _, line := range []string{`status=200 status=500`, `method="unterminated`} {
		if _, err := l.Parse(line); err == nil {
			t.Fatal("invalid logfmt accepted")
		}
	}
}

func TestStructuredTimestampStorageBounds(t *testing.T) {
	for _, mode := range []string{"rfc3339", "unix_ms", "unix_s"} {
		s, err := NewSource(config.AccessFile{Site: "shop", Format: "json", Profile: "epoch"}, map[string]config.LogProfile{"epoch": {Timestamp: mode}})
		if err != nil {
			t.Fatal(err)
		}
		bad := "9223372036854775807"
		if mode == "rfc3339" {
			bad = "9999-01-01T00:00:00Z"
		}
		line := `{"timestamp":"` + bad + `","client_ip":"192.0.2.1","method":"GET","path":"/","status":200}`
		if _, err := s.Parse(line); err == nil {
			t.Fatal("timestamp overflows stored nanoseconds", mode)
		}
	}
}

func BenchmarkStructuredLogfmt(b *testing.B) {
	s, _ := NewSource(config.AccessFile{Site: "shop", Format: "logfmt"}, nil)
	line := `timestamp=2026-10-03T12:00:00Z client_ip=192.0.2.1 method=GET path=/ status=200`
	b.ReportAllocs()
	for j := 0; j < b.N; j++ {
		if _, err := s.Parse(line); err != nil {
			b.Fatal(err)
		}
	}
}
func TestErrorParsersAndRedaction(t *testing.T) {
	for _, test := range []struct{ format, line string }{{"nginx-error", `2026/10/03 12:00:00 [error] 1#1: *8 upstream timed out, client: 2001:db8::1, request: "GET /api?token=abc HTTP/1.1", upstream: "http://127.0.0.1:9000/api?secret=x"`}, {"apache-error", `[Sat Oct 03 12:00:00.000001 2026] [proxy:error] [pid 1] [client 192.0.2.1:1234] [R:abc] AH01075: timeout password=abc /var/www/private.php`}, {"apache-error", `[Sat Oct 03 12:00:00.000001 2026] [proxy:error] [pid 1] [client [2001:db8::1]:1234] AH01075: timeout`}} {
		s, _ := NewSource(config.AccessFile{Format: test.format, Site: "shop", Kind: "error"}, nil)
		e, err := s.ParseError(test.line)
		if err != nil {
			t.Fatal(err)
		}
		if !e.ClientIP.IsValid() || e.Severity != "error" || e.Fingerprint == "" || strings.Contains(e.Message, "password=abc") || strings.Contains(e.Message, "secret=x") || strings.Contains(e.Message, "/var/www") {
			t.Fatalf("unsafe or incomplete error: %+v", e)
		}
	}
}
func BenchmarkStructuredJSON(b *testing.B) {
	s, _ := NewSource(config.AccessFile{Site: "shop", Format: "json"}, nil)
	line := `{"timestamp":"2026-10-03T12:00:00Z","client_ip":"192.0.2.1","method":"GET","path":"/","status":200}`
	b.ReportAllocs()
	for j := 0; j < b.N; j++ {
		if _, err := s.Parse(line); err != nil {
			b.Fatal(err)
		}
	}
}
