package aggregator

import (
	"net/url"
	"strings"
)

// Classification adds fixed counters only: no unbounded path index or I/O.
// Match common WordPress endpoints, including installations in a subdirectory.
func wordPressEndpoint(path, query string) bool {
	if strings.Contains(path, "%") {
		path = CanonicalPath(path)
	}
	base := path[strings.LastIndexByte(path, '/')+1:]
	switch base {
	case "wp-login.php", "xmlrpc.php":
		return true
	case "admin-ajax.php":
		if strings.HasSuffix(path, "/wp-admin/admin-ajax.php") {
			return true
		}
	}
	if strings.HasSuffix(base, ".xml") && (strings.HasPrefix(base, "wp-sitemap") || strings.HasPrefix(base, "sitemap") || strings.Contains(base, "-sitemap")) {
		return true
	}
	if strings.Contains(path, "/wp-json/") || strings.HasSuffix(path, "/wp-json") || strings.HasSuffix(path, "/feed/") || strings.HasSuffix(path, "/feed") {
		return true
	}
	// Inspect bounded keys only; never retain search terms or other query values.
	for query != "" {
		part, rest, _ := strings.Cut(query, "&")
		query = rest
		key, _, _ := strings.Cut(part, "=")
		if strings.Contains(key, "%") {
			decoded, err := url.QueryUnescape(key)
			if err != nil {
				continue
			}
			key = decoded
		}
		switch key {
		case "s", "rest_route", "wc-ajax", "feed":
			return true
		}
	}
	return false
}
