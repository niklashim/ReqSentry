package parser

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/niklashim/ReqSentry/internal/model"
)

var nginxError = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[([a-z]+)\] (.*)$`)
var apacheError = regexp.MustCompile(`^\[([^]]+)\] \[([^]]+)\](.*)$`)
var errorClient = regexp.MustCompile(`(?:client: |\[client )(\[[^]]+\](?::[0-9]+)?|[^,\] ]+)`)
var errorRequest = regexp.MustCompile(`request: "([^"]+)"`)
var connectionID = regexp.MustCompile(`\*(\d+)`)
var requestID = regexp.MustCompile(`\[R:([^]]+)\]`)
var errorCode = regexp.MustCompile(`\bAH[0-9]{5}\b`)
var secretValue = regexp.MustCompile(`(?i)(authorization|password|passwd|token|secret|cookie|api[_-]?key|signature)[=: ]+[^ ,;]+`)
var urls = regexp.MustCompile(`https?://[^\s"']+`)
var privatePaths = regexp.MustCompile(`/[^\s"',;]+`)
var digits = regexp.MustCompile(`[0-9]+`)

func RedactMessage(v string) string {
	v = urls.ReplaceAllString(v, "<url>")
	v = secretValue.ReplaceAllString(v, "$1=<redacted>")
	v = privatePaths.ReplaceAllString(v, "<path>")
	v = strings.ReplaceAll(strings.ReplaceAll(v, "\r", " "), "\n", " ")
	if len(v) > 1024 {
		v = v[:1024]
		for !utf8.ValidString(v) {
			v = v[:len(v)-1]
		}
		v += "… [truncated]"
	}
	return v
}
func Severity(v string) string {
	switch strings.ToLower(v) {
	case "warn":
		return "warning"
	case "err":
		return "error"
	case "crit", "fatal":
		return "critical"
	case "emerg":
		return "emergency"
	case "trace":
		return "debug"
	}
	return strings.ToLower(v)
}
func SeverityRank(v string) int {
	switch Severity(v) {
	case "debug":
		return 0
	case "info":
		return 1
	case "notice":
		return 2
	case "warning":
		return 3
	case "error":
		return 4
	case "critical":
		return 5
	case "alert":
		return 6
	case "emergency":
		return 7
	}
	return -1
}
func (s *Source) ParseError(line string) (model.ErrorEvent, error) {
	e := model.ErrorEvent{Source: s.File.Path, SiteID: s.File.Site, IngestedAt: time.Now().UTC(), Identity: "unknown"}
	var message string
	var err error
	switch s.File.Format {
	case "nginx-error":
		m := nginxError.FindStringSubmatch(line)
		if m == nil {
			return e, errors.New("unsupported Nginx error record")
		}
		e.Timestamp, err = time.ParseInLocation("2006/01/02 15:04:05", m[1], s.zone)
		e.Severity = Severity(m[2])
		message = m[3]
		if id := connectionID.FindStringSubmatch(message); id != nil {
			e.ConnectionID = id[1]
		}
	case "apache-error":
		m := apacheError.FindStringSubmatch(line)
		if m == nil {
			return e, errors.New("unsupported Apache error record")
		}
		for _, layout := range []string{"Mon Jan 02 15:04:05.000000 2006", "Mon Jan 02 15:04:05 2006", "Mon Jan _2 15:04:05.000000 2006", "Mon Jan _2 15:04:05 2006"} {
			e.Timestamp, err = time.ParseInLocation(layout, m[1], s.zone)
			if err == nil {
				break
			}
		}
		level := strings.Split(m[2], ":")
		e.Severity = Severity(level[len(level)-1])
		message = m[3]
		if id := requestID.FindStringSubmatch(message); id != nil {
			e.RequestID = boundedID(id[1])
		}
		if code := errorCode.FindString(message); code != "" {
			e.Code = code
		}
	case "json", "logfmt":
		values, valueErr := s.values(line)
		if valueErr != nil {
			return e, valueErr
		}
		get := func(k string) string { return s.value(values, k) }
		e.Timestamp, err = s.timestamp(get("timestamp"))
		e.Severity = Severity(get("severity"))
		message = get("message")
		if s.File.RetainStackTrace {
			e.StackTrace = RedactMessage(get("stack_trace"))
		}
		e.Code = boundedID(get("error_code"))
		e.Category = boundedID(get("error_type"))
		e.RequestID = boundedID(get("request_id"))
		e.TraceID = boundedID(get("trace_id"))
		e.Path = safeErrorPath(get("path"))
		if ip, ipErr := netip.ParseAddr(get("client_ip")); ipErr == nil {
			e.ClientIP = ip.Unmap()
			e.Identity = "logged"
		}
		if peer := get("peer"); available(peer) {
			ip, ipErr := netip.ParseAddr(peer)
			if ipErr != nil {
				return e, errors.New("invalid error peer")
			}
			e.ClientIP = ip.Unmap()
			e.Identity = "peer"
		}
	default:
		return e, errors.New("unsupported error format")
	}
	if err != nil || e.Timestamp.IsZero() {
		return e, errors.New("invalid error timestamp")
	}
	if SeverityRank(e.Severity) < 0 || message == "" {
		return e, errors.New("missing error severity/message")
	}
	if s.File.Format == "nginx-error" || s.File.Format == "apache-error" {
		if match := errorClient.FindStringSubmatch(message); match != nil {
			v := match[1]
			if ip, err := netip.ParseAddr(v); err == nil {
				e.ClientIP = ip.Unmap()
				e.Identity = "logged"
			} else if pair, err := netip.ParseAddrPort(v); err == nil {
				e.ClientIP = pair.Addr().Unmap()
				e.Identity = "logged"
			}
		}
		if match := errorRequest.FindStringSubmatch(message); match != nil {
			_, path, _, err := parseRequest(match[1])
			if err == nil {
				e.Path = safeErrorPath(path)
			}
		}
	}
	if e.Category == "" {
		switch {
		case strings.Contains(message, "timed out") || strings.Contains(message, "timeout"):
			e.Category = "upstream_timeout"
		case strings.Contains(message, "Connection refused") || strings.Contains(message, "connection refused"):
			e.Category = "upstream_refused"
		case strings.Contains(message, "No such file") || strings.Contains(message, "does not exist"):
			e.Category = "missing_file"
		case strings.Contains(message, "too many open files") || strings.Contains(message, "worker_connections") || strings.Contains(message, "Cannot allocate memory"):
			e.Category = "resource_limit"
		default:
			e.Category = "other"
		}
	}
	e.Message = RedactMessage(message)
	h := sha256.Sum256([]byte(e.Category + "|" + e.Code + "|" + digits.ReplaceAllString(e.Message, "#")))
	e.Fingerprint = "v1:" + hex.EncodeToString(h[:12])
	return e, nil
}
func safeErrorPath(v string) string {
	if !strings.HasPrefix(v, "/") || len(v) > 256 {
		return ""
	}
	v, _, _ = strings.Cut(v, "?")
	return v
}
