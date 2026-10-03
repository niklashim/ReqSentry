package model

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSampleOmitsRawSensitiveFieldsAndBoundsStrings(t *testing.T) {
	r := RequestEvent{SiteID: "shop", Method: "GET\nFORGED", Path: "/login?token=secret", Query: "password=secret", RequestID: strings.Repeat("世", 100), ForwardedFor: "secret"}
	s := SampleRequest(r)
	if s.Path != "/login" || strings.Contains(s.Method, "\n") || len(s.RequestID) > 128 || !utf8.ValidString(s.RequestID) {
		t.Fatalf("unsafe sample: %+v", s)
	}
	for _, path := range []string{strings.Repeat("世", 200), strings.Repeat("a", 255) + "世", "\xff" + strings.Repeat("a", 1000)} {
		s := SampleRequest(RequestEvent{Path: path})
		if len(s.Path) > 256 || !utf8.ValidString(s.Path) {
			t.Fatal("path byte/UTF bounds violated")
		}
	}
}
