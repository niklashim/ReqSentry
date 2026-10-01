// Package parser converts Nginx and Apache combined access logs into a common
// event. Both servers can append ReqSentry's documented optional fields.
package parser

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/niklashim/ReqSentry/internal/model"
)

const timeLayout = "02/Jan/2006:15:04:05 -0700"

// Parse accepts common/combined Nginx and Apache lines. The configured site
// is authoritative; a logged host is additional evidence, never a site key.
func Parse(line, site string) (model.RequestEvent, error) {
	fields, err := splitFields(line)
	if err != nil {
		return model.RequestEvent{}, err
	}
	if site == "" {
		return model.RequestEvent{}, errors.New("site is missing")
	}
	var event model.RequestEvent
	event.SiteID = site
	if len(fields) < 7 {
		return event, errors.New("access log has too few fields")
	}
	base := 0
	ip, err := netip.ParseAddr(fields[0])
	if err != nil && len(fields) >= 8 {
		// Apache's virtual-host common format may prefix the client IP with %v.
		ip, err = netip.ParseAddr(fields[1])
		if err == nil {
			event.Host = fields[0]
			base = 1
		}
	}
	if err != nil {
		return event, errors.New("invalid client IP")
	}
	if len(fields) < base+7 {
		return event, errors.New("access log has too few fields")
	}
	event.ClientIP = ip.Unmap()
	event.LogIP = event.ClientIP
	event.PeerIP = event.ClientIP
	event.Timestamp, err = time.Parse(timeLayout, fields[base+3])
	if err != nil {
		return event, errors.New("invalid access-log timestamp")
	}
	event.Method, event.Path, event.Query, err = parseRequest(fields[base+4])
	if err != nil {
		return event, err
	}
	event.Status, err = strconv.Atoi(fields[base+5])
	if err != nil || event.Status < 100 || event.Status > 599 {
		return event, errors.New("invalid HTTP status")
	}
	if fields[base+6] != "-" {
		value, err := strconv.ParseInt(fields[base+6], 10, 64)
		if err != nil || value < 0 {
			return event, errors.New("invalid response bytes")
		}
		event.Bytes = &value
	}

	index := base + 7
	if index < len(fields) && !isExtension(fields[index]) {
		if fields[index] != "-" {
			value := fields[index]
			event.Referrer = &value
		}
		index++
	}
	if index < len(fields) && !isExtension(fields[index]) {
		if fields[index] != "-" {
			value := fields[index]
			event.UserAgent = &value
		}
		index++
	}
	seen := make(map[string]bool)
	for ; index < len(fields); index++ {
		key, value, ok := strings.Cut(fields[index], "=")
		if !ok || seen[key] {
			return event, errors.New("invalid optional access-log field")
		}
		seen[key] = true
		switch key {
		case "host":
			if value != "-" && value != "" {
				event.Host = value
			}
		case "rt":
			event.RequestTime, err = parseSeconds(value)
		case "rt_us":
			event.RequestTime, err = parseMicroseconds(value)
		case "urt":
			// Multiple upstream attempts have no single meaningful duration.
			if !strings.ContainsAny(value, ",:") {
				event.UpstreamTime, err = parseSeconds(value)
			}
		case "peer":
			if value != "-" && value != "" {
				peer, parseErr := netip.ParseAddr(value)
				if parseErr != nil {
					return event, errors.New("invalid peer IP")
				}
				event.PeerIP = peer.Unmap()
			}
		case "xff":
			if value != "-" {
				event.ForwardedFor = value
			}
		case "cfip":
			if value != "-" {
				event.CFConnectingIP = value
			}
		case "xrealip":
			if value != "-" {
				event.XRealIP = value
			}
		case "loc":
			if value != "-" && value != "" {
				event.Location = &value
			}
		default:
			return event, fmt.Errorf("unsupported optional access-log field %q", key)
		}
		if err != nil {
			return event, fmt.Errorf("invalid %s duration", key)
		}
	}
	return event, nil
}

func isExtension(value string) bool {
	for _, prefix := range []string{"host=", "rt=", "rt_us=", "urt=", "peer=", "xff=", "cfip=", "xrealip=", "loc="} {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func parseRequest(request string) (method, path, query string, err error) {
	first := strings.IndexByte(request, ' ')
	if first <= 0 {
		return "", "", "", errors.New("invalid HTTP request line")
	}
	method = request[:first]
	for i := 0; i < len(method); i++ {
		ch := method[i]
		if !((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(ch))) {
			return "", "", "", errors.New("invalid HTTP method")
		}
	}
	target := strings.TrimSpace(request[first+1:])
	if last := strings.LastIndexByte(target, ' '); last > 0 && strings.HasPrefix(target[last+1:], "HTTP/") {
		target = target[:last]
	}
	if target == "" {
		return "", "", "", errors.New("missing request target")
	}
	if target == "*" {
		return method, target, "", nil
	}
	if _, err := url.PathUnescape(target); err != nil {
		return "", "", "", errors.New("invalid request target escaping")
	}
	parsed, err := url.ParseRequestURI(target)
	if err != nil {
		return "", "", "", errors.New("invalid request target")
	}
	path = parsed.EscapedPath()
	if path == "" {
		return "", "", "", errors.New("request path is missing")
	}
	return method, path, parsed.RawQuery, nil
}

func parseSeconds(value string) (*time.Duration, error) {
	if value == "-" || value == "" {
		return nil, nil
	}
	duration, err := time.ParseDuration(value + "s")
	if err != nil || duration < 0 {
		return nil, errors.New("invalid seconds")
	}
	return &duration, nil
}

func parseMicroseconds(value string) (*time.Duration, error) {
	if value == "-" || value == "" {
		return nil, nil
	}
	count, err := strconv.ParseInt(value, 10, 64)
	if err != nil || count < 0 || count > math.MaxInt64/int64(time.Microsecond) {
		return nil, errors.New("invalid microseconds")
	}
	duration := time.Duration(count) * time.Microsecond
	return &duration, nil
}

func splitFields(line string) ([]string, error) {
	var fields []string
	var current strings.Builder
	quoted := false
	bracketed := false
	started := false
	flush := func() {
		if started {
			fields = append(fields, current.String())
			current.Reset()
			started = false
		}
	}
	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch {
		case ch == ' ' || ch == '\t':
			if !quoted && !bracketed {
				flush()
			} else {
				current.WriteByte(ch)
			}
		case ch == '"' && !bracketed:
			quoted = !quoted
			started = true
		case ch == '[' && !quoted && !started:
			bracketed = true
			started = true
		case ch == ']' && bracketed:
			bracketed = false
		case ch == '\\' && quoted:
			if i+1 >= len(line) {
				return nil, errors.New("incomplete escape in access log")
			}
			i++
			switch line[i] {
			case '"', '\\':
				current.WriteByte(line[i])
			case 'n':
				current.WriteByte('\n')
			case 'r':
				current.WriteByte('\r')
			case 't':
				current.WriteByte('\t')
			case 'x':
				if i+2 >= len(line) {
					return nil, errors.New("incomplete hex escape in access log")
				}
				value, err := strconv.ParseUint(line[i+1:i+3], 16, 8)
				if err != nil {
					return nil, errors.New("invalid hex escape in access log")
				}
				current.WriteByte(byte(value))
				i += 2
			default:
				return nil, errors.New("unsupported escape in access log")
			}
			started = true
		default:
			current.WriteByte(ch)
			started = true
		}
	}
	if quoted || bracketed {
		return nil, errors.New("unterminated quoted or timestamp field")
	}
	flush()
	return fields, nil
}
