package model

import (
	"net/netip"
	"strings"
	"time"
	"unicode"
)

const MaxRequestSamples = 5

// RequestSample is normalized investigation evidence, never a raw log line.
// Query strings, referrers, forwarded headers and request bodies are omitted.
type RequestSample struct {
	Timestamp time.Time  `json:"timestamp"`
	SiteID    string     `json:"site_id"`
	ClientIP  netip.Addr `json:"client_ip"`
	Method    string     `json:"method"`
	Path      string     `json:"path"`
	Status    int        `json:"status"`
	RequestID string     `json:"request_id,omitempty"`
	TraceID   string     `json:"trace_id,omitempty"`
	Bytes     *int64     `json:"bytes,omitempty"`
	RequestMS *float64   `json:"request_ms,omitempty"`
}

func SampleRequest(r RequestEvent) RequestSample {
	path, _, _ := strings.Cut(SampleText(r.Path, 256), "?")
	s := RequestSample{Timestamp: r.Timestamp, SiteID: SampleText(r.SiteID, 128), ClientIP: r.ClientIP.Unmap(), Method: SampleText(r.Method, 32), Path: path, Status: r.Status, RequestID: SampleText(r.RequestID, 128), TraceID: SampleText(r.TraceID, 128)}
	if r.Bytes != nil && *r.Bytes >= 0 {
		v := *r.Bytes
		s.Bytes = &v
	}
	if r.RequestTime != nil && *r.RequestTime >= 0 {
		v := float64(*r.RequestTime) / float64(time.Millisecond)
		s.RequestMS = &v
	}
	return s
}

func CloneRequestSamples(samples []RequestSample) []RequestSample {
	if len(samples) > MaxRequestSamples {
		samples = samples[:MaxRequestSamples]
	}
	if len(samples) == 0 {
		return nil
	}
	out := append([]RequestSample(nil), samples...)
	for i := range out {
		if out[i].Bytes != nil {
			v := *out[i].Bytes
			out[i].Bytes = &v
		}
		if out[i].RequestMS != nil {
			v := *out[i].RequestMS
			out[i].RequestMS = &v
		}
	}
	return out
}

// Clone string storage so a short sample cannot retain a large input line.
func SampleText(v string, limit int) string {
	if len(v) > limit {
		v = v[:limit]
	}
	v = strings.ToValidUTF8(v, "")
	return strings.Clone(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, v))
}
