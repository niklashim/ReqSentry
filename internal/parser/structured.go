package parser

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/go-logfmt/logfmt"
	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
)

type Source struct {
	File      config.AccessFile
	profile   config.LogProfile
	fields    map[string]string
	selectors map[string][]string
	zone      *time.Location
}

func NewSource(file config.AccessFile, profiles map[string]config.LogProfile) (*Source, error) {
	p := config.LogProfile{}
	if file.Profile != "" {
		var ok bool
		p, ok = profiles[file.Profile]
		if !ok {
			return nil, errors.New("unknown source profile")
		}
	}
	zone := time.UTC
	var err error
	if file.Timezone != "" {
		zone, err = time.LoadLocation(file.Timezone)
		if err != nil {
			return nil, errors.New("invalid source timezone")
		}
	}
	fields := map[string]string{}
	for _, k := range config.LogFields {
		fields[k] = k
	}
	fields["peer"] = "peer_ip"
	fields["xff"] = "forwarded_for"
	fields["cfip"] = "cf_connecting_ip"
	fields["xrealip"] = "x_real_ip"
	if p.Preset == "ecs" || p.Preset == "ecs-v1" {
		fields = map[string]string{"timestamp": "@timestamp", "client_ip": "/client/ip", "peer": "/source/ip", "method": "/http/request/method", "path": "/url/path", "query": "/url/query", "status": "/http/response/status_code", "bytes": "/http/response/body/bytes", "host": "/url/domain", "user_agent": "/user_agent/original", "request_time": "/event/duration", "request_id": "/http/request/id", "trace_id": "/trace/id", "severity": "/log/level", "message": "/error/message", "error_type": "/error/type", "error_code": "/error/code", "stack_trace": "/error/stack_trace"}
		if p.DurationUnit == "" {
			p.DurationUnit = "ns"
		}
	}
	for k, v := range p.Fields {
		fields[k] = v
	}
	if p.Timestamp == "" {
		p.Timestamp = "rfc3339"
	}
	if p.DurationUnit == "" {
		p.DurationUnit = "s"
	}
	selectors := map[string][]string{}
	for k, v := range fields {
		if strings.HasPrefix(v, "/") {
			parts := strings.Split(v[1:], "/")
			for i := range parts {
				parts[i] = strings.ReplaceAll(strings.ReplaceAll(parts[i], "~1", "/"), "~0", "~")
			}
			selectors[k] = parts
		}
	}
	return &Source{File: file, profile: p, fields: fields, selectors: selectors, zone: zone}, nil
}
func (s *Source) Parse(line string) (model.RequestEvent, error) {
	if s.File.Format == "" || s.File.Format == "combined" {
		return Parse(line, s.File.Site)
	}
	values, err := s.values(line)
	if err != nil {
		return model.RequestEvent{}, err
	}
	get := func(k string) string { return s.value(values, k) }
	var e model.RequestEvent
	e.SiteID = s.File.Site
	e.Timestamp, err = s.timestamp(get("timestamp"))
	if err != nil {
		return e, err
	}
	e.ClientIP, err = netip.ParseAddr(get("client_ip"))
	if err != nil {
		return e, errors.New("invalid client IP")
	}
	e.ClientIP = e.ClientIP.Unmap()
	e.LogIP = e.ClientIP
	e.PeerIP = e.ClientIP
	if v := get("peer"); v != "" && v != "-" {
		e.PeerIP, err = netip.ParseAddr(v)
		if err != nil {
			return e, errors.New("invalid peer IP")
		}
		e.PeerIP = e.PeerIP.Unmap()
	}
	target := get("target")
	if target == "" {
		target = get("path")
		if q := get("query"); q != "" {
			target += "?" + q
		}
	}
	e.Method, e.Path, e.Query, err = parseRequest(get("method") + " " + target)
	if err != nil {
		return e, err
	}
	e.Status, err = strconv.Atoi(get("status"))
	if err != nil || e.Status < 100 || e.Status > 599 {
		return e, errors.New("invalid HTTP status")
	}
	if v := get("bytes"); available(v) {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return e, errors.New("invalid response bytes")
		}
		e.Bytes = &n
	}
	e.RequestTime, err = s.duration(get("request_time"))
	if err != nil {
		return e, err
	}
	if v := get("upstream_time"); !strings.ContainsAny(v, ",:") {
		e.UpstreamTime, err = s.duration(v)
		if err != nil {
			return e, err
		}
	}
	e.Host = get("host")
	e.ForwardedFor = get("xff")
	e.CFConnectingIP = get("cfip")
	e.XRealIP = get("xrealip")
	optional := func(k string) *string {
		v := get(k)
		if !available(v) {
			return nil
		}
		return &v
	}
	e.UserAgent = optional("user_agent")
	e.Referrer = optional("referrer")
	e.Location = optional("location")
	e.RequestID = boundedID(get("request_id"))
	e.TraceID = boundedID(get("trace_id"))
	return e, nil
}
func available(s string) bool { return s != "" && s != "-" && s != "null" }
func boundedID(s string) string {
	if len(s) > 128 || strings.ContainsAny(s, "\r\n\x00") {
		return ""
	}
	return s
}
func (s *Source) duration(v string) (*time.Duration, error) {
	if !available(v) {
		return nil, nil
	}
	n, err := strconv.ParseFloat(v, 64)
	multiplier := float64(time.Second)
	switch s.profile.DurationUnit {
	case "ms":
		multiplier = float64(time.Millisecond)
	case "us":
		multiplier = float64(time.Microsecond)
	case "ns":
		multiplier = 1
	}
	n *= multiplier
	if err != nil || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 || n >= float64(math.MaxInt64) {
		return nil, errors.New("invalid duration")
	}
	d := time.Duration(n)
	return &d, nil
}
func (s *Source) timestamp(v string) (time.Time, error) {
	if s.profile.Timestamp == "rfc3339" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil || t.Before(time.Unix(0, math.MinInt64)) || t.After(time.Unix(0, math.MaxInt64)) {
			return t, errors.New("invalid timestamp")
		}
		return t, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return time.Time{}, errors.New("invalid epoch timestamp")
	}
	switch s.profile.Timestamp {
	case "unix_s":
		if n > math.MaxInt64/1000000000 || n < math.MinInt64/1000000000 {
			return time.Time{}, errors.New("epoch overflow")
		}
		return time.Unix(n, 0), nil
	case "unix_ms":
		if n > math.MaxInt64/1000000 || n < math.MinInt64/1000000 {
			return time.Time{}, errors.New("epoch overflow")
		}
		return time.Unix(n/1000, (n%1000)*1e6), nil
	case "unix_ns":
		return time.Unix(0, n), nil
	}
	return time.Time{}, errors.New("unsupported timestamp")
}
func (s *Source) value(values map[string]any, k string) string {
	selector, ok := s.fields[k]
	if !ok {
		return ""
	}
	var v any = values
	if strings.HasPrefix(selector, "/") {
		for _, part := range s.selectors[k] {
			m, ok := v.(map[string]any)
			if !ok {
				return ""
			}
			v = m[part]
		}
	} else {
		v = values[selector]
	}
	switch x := v.(type) {
	case string:
		if len(x) <= 65536 {
			return x
		}
	case json.Number:
		return x.String()
	}
	return ""
}
func (s *Source) values(line string) (map[string]any, error) {
	if len(line) > 1<<20 {
		return nil, errors.New("record exceeds 1 MiB")
	}
	if s.File.Format == "logfmt" {
		d := logfmt.NewDecoder(strings.NewReader(line))
		m := map[string]any{}
		if !d.ScanRecord() {
			return nil, errors.New("empty logfmt record")
		}
		for d.ScanKeyval() {
			k := string(d.Key())
			if len(k) > 256 || len(d.Value()) > 65536 || len(m) >= 256 {
				return nil, errors.New("logfmt field limit")
			}
			if _, ok := m[k]; ok {
				return nil, errors.New("duplicate logfmt key")
			}
			m[k] = string(d.Value())
		}
		if d.Err() != nil {
			return nil, errors.New("invalid logfmt quoting")
		}
		if d.ScanRecord() {
			return nil, errors.New("multiple logfmt records")
		}
		return m, nil
	}
	d := json.NewDecoder(strings.NewReader(line))
	d.UseNumber()
	count := 0
	v, err := jsonValue(d, 0, &count)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON content")
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("JSON record must be an object")
	}
	return m, nil
}
func jsonValue(d *json.Decoder, depth int, count *int) (any, error) {
	if depth > 16 || *count > 4096 {
		return nil, errors.New("JSON structure limit")
	}
	*count++
	token, err := d.Token()
	if err != nil {
		return nil, errors.New("invalid JSON")
	}
	switch t := token.(type) {
	case json.Delim:
		if t == '{' {
			m := map[string]any{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return nil, errors.New("invalid JSON key")
				}
				k, ok := key.(string)
				if !ok || len(k) > 256 {
					return nil, errors.New("invalid JSON key")
				}
				if _, ok := m[k]; ok {
					return nil, errors.New("duplicate JSON key")
				}
				v, err := jsonValue(d, depth+1, count)
				if err != nil {
					return nil, err
				}
				m[k] = v
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return nil, errors.New("invalid JSON object")
			}
			return m, nil
		}
		if t == '[' {
			a := []any{}
			for d.More() {
				v, err := jsonValue(d, depth+1, count)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return nil, errors.New("invalid JSON array")
			}
			return a, nil
		}
		return nil, errors.New("unexpected JSON delimiter")
	case string:
		if len(t) > 65536 {
			return nil, errors.New("JSON string limit")
		}
		return t, nil
	default:
		return token, nil
	}
}
func (s *Source) String() string { return fmt.Sprintf("%s:%s", s.File.Site, s.File.Format) }
