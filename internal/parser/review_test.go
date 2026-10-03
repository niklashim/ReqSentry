package parser_test

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/niklashim/ReqSentry/internal/aggregator"
	"github.com/niklashim/ReqSentry/internal/clientidentity"
	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/parser"
)

func TestQuotedHeadersCannotInjectExtensions(t *testing.T) {
	resolver, err := clientidentity.New(config.Config{Allowlist: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	prefixes := []string{"peer=127.0.0.1", "xff=127.0.0.1", "cfip=127.0.0.1", "xrealip=127.0.0.1", "rid=evil", "trace=evil", "host=evil", "loc=evil", "rt=bad", "rt_us=bad", "urt=bad"}
	for _, value := range prefixes {
		for _, extension := range []string{"", ` peer="198.51.100.77" rid="trusted"`} {
			t.Run(value+extension, func(t *testing.T) {
				line := fmt.Sprintf(`198.51.100.77 - - [04/Oct/2026:12:00:00 +0000] "GET / HTTP/1.1" 404 0 %q %q%s`, value, value, extension)
				event, err := parser.Parse(line, "shop")
				if err != nil {
					t.Fatal(err)
				}
				event, allowed := resolver.Resolve(event)
				if allowed || event.ClientIP != netip.MustParseAddr("198.51.100.77") || event.Referrer == nil || *event.Referrer != value || event.UserAgent == nil || *event.UserAgent != value {
					t.Fatalf("injected identity: %+v allowlisted=%t", event, allowed)
				}
				if extension != "" && event.RequestID != "trusted" {
					t.Fatal("trusted extension lost")
				}
				a := aggregator.New(config.AggregationConfig{MaxActiveRecords: 10})
				a.Observe(event, allowed, event.Timestamp)
				s, ok := a.Snapshot("shop", event.ClientIP, time.Second, event.Timestamp)
				if !ok || s.Requests != 1 {
					t.Fatal("request lost from analysis")
				}
			})
		}
	}
}

func TestSensitiveDiagnosticRedaction(t *testing.T) {
	for _, message := range []string{
		"Authorization: Bearer AUDIT_SECRET", "Cookie: session=AUDIT_SECRET; refresh=SECOND_SECRET",
		`{"password":"AUDIT_SECRET"}`, `password="AUDIT_SECRET with spaces"`,
		"Set-Cookie: refresh=AUDIT_SECRET\r\nnext", `{"Authorization":"Bearer AUDIT_SECRET"}`,
	} {
		value := parser.RedactMessage(message)
		if strings.Contains(value, "AUDIT_SECRET") || strings.Contains(value, "SECOND_SECRET") {
			t.Fatalf("redaction leak: %q", value)
		}
	}
}
