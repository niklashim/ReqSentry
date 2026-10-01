// Package detector derives explainable behavioral signals from bounded
// traffic snapshots. Scoring and incident output are separate later steps.
package detector

import (
	"math"
	"sort"
	"strings"

	"github.com/niklashim/ReqSentry/internal/aggregator"
	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
)

// HTTP uses the initial monitor-mode thresholds.
func HTTP(snapshot aggregator.Snapshot) []model.Signal {
	return HTTPWithRules(snapshot, config.DefaultDetectionConfig())
}

func HTTPWithRules(snapshot aggregator.Snapshot, rules config.DetectionConfig) []model.Signal {
	t := thresholds(rules)
	var signals []model.Signal
	requests := snapshot.Requests
	if requests == 0 {
		return signals
	}
	notFound := snapshot.ImportantStatuses[404]
	if float64(requests) >= t["high_404_min_requests"] && float64(notFound) >= t["high_404_min_count"] && ratio(notFound, requests) >= t["high_404_ratio"] {
		signals = append(signals, signal("HIGH_404_RATE", model.SignalBehavioral, map[string]any{
			"requests": requests, "status_404": notFound, "ratio": ratio(notFound, requests),
		}))
	}
	if float64(notFound) >= t["high_404_min_count"] && float64(snapshot.Unique404Paths) >= t["unique_404_min"] && (snapshot.Saturation.MissingPaths || ratio(uint64(snapshot.Unique404Paths), notFound) >= t["unique_404_ratio"]) {
		signals = append(signals, signal("HIGH_404_DIVERSITY", model.SignalStrong, map[string]any{
			"status_404": notFound, "unique_404_at_least": snapshot.Unique404Paths,
			"saturated": snapshot.Saturation.MissingPaths,
		}))
	}
	pathPatterns := make(map[string]int)
	for _, path := range snapshot.MissingPathSamples {
		pattern := NormalizePath(path)
		if pattern != path {
			pathPatterns[pattern]++
		}
	}
	orderedPatterns := make([]string, 0, len(pathPatterns))
	for pattern := range pathPatterns {
		orderedPatterns = append(orderedPatterns, pattern)
	}
	sort.Strings(orderedPatterns)
	for _, pattern := range orderedPatterns {
		unique := pathPatterns[pattern]
		if float64(unique) >= t["path_enumeration_min"] {
			signals = append(signals, signal("PATH_ENUMERATION", model.SignalStrong, map[string]any{
				"pattern": pattern, "distinct_paths_at_least": unique,
			}))
		}
	}
	if len(snapshot.QueryPatternSamples) == 1 && !snapshot.Saturation.QueryPatterns && strings.Contains(snapshot.QueryPatternSamples[0], "{NUMBER}") && float64(snapshot.UniqueQueryValues) >= t["query_enumeration_min"] {
		signals = append(signals, signal("QUERY_ENUMERATION", model.SignalStrong, map[string]any{
			"pattern": snapshot.QueryPatternSamples[0], "distinct_targets_at_least": snapshot.UniqueQueryValues,
			"saturated": snapshot.Saturation.QueryValues,
		}))
	}
	seconds := snapshot.Window.Seconds()
	if seconds > 0 {
		rate := float64(requests) / seconds
		if float64(requests) >= t["high_rate_min_requests"] && rate >= t["high_rate_rps"] {
			signals = append(signals, signal("HIGH_REQUEST_RATE", model.SignalBehavioral, map[string]any{
				"requests": requests, "window_seconds": seconds, "average_rps": rate,
			}))
		}
		if float64(snapshot.PeakRPS) >= t["burst_rps"] {
			signals = append(signals, signal("HIGH_BURST_RATE", model.SignalBehavioral, map[string]any{
				"peak_rps": snapshot.PeakRPS,
			}))
		}
		if seconds >= 10 && snapshot.ActiveSeconds >= int(math.Ceil(seconds*t["sustained_active_ratio"])) && rate >= t["sustained_rps"] {
			signals = append(signals, signal("SUSTAINED_HIGH_RATE", model.SignalBehavioral, map[string]any{
				"active_seconds": snapshot.ActiveSeconds, "window_seconds": seconds, "average_rps": rate,
			}))
		}
	}
	serverErrors := snapshot.StatusFamilies[5]
	if float64(requests) >= t["high_5xx_min_requests"] && float64(serverErrors) >= t["high_5xx_min_count"] && ratio(serverErrors, requests) >= t["high_5xx_ratio"] {
		signals = append(signals, signal("HIGH_5XX_CONTRIBUTION", model.SignalBehavioral, map[string]any{
			"requests": requests, "status_5xx": serverErrors, "ratio": ratio(serverErrors, requests),
		}))
	}
	redirects := snapshot.ImportantStatuses[301] + snapshot.ImportantStatuses[302]
	if float64(requests) >= t["redirect_min_requests"] && float64(redirects) >= t["redirect_min_count"] && ratio(redirects, requests) >= t["redirect_ratio"] {
		followBehavior := "unavailable"
		if snapshot.RedirectKnown > 0 {
			followBehavior = "observed"
		}
		signals = append(signals, signal("HIGH_REDIRECT_RATIO", model.SignalSupporting, map[string]any{
			"requests": requests, "redirects": redirects, "ratio": ratio(redirects, requests),
			"follow_behavior": followBehavior, "redirects_with_targets": snapshot.RedirectKnown,
			"followed_targets": snapshot.RedirectFollows,
		}))
	}
	unsafe404 := snapshot.Method404["POST"] + snapshot.Method404["PUT"] + snapshot.Method404["PATCH"] + snapshot.Method404["DELETE"] + snapshot.Method404["OPTIONS"]
	unsafeUnique := snapshot.Method404UniquePaths["POST"] + snapshot.Method404UniquePaths["PUT"] + snapshot.Method404UniquePaths["PATCH"] + snapshot.Method404UniquePaths["DELETE"] + snapshot.Method404UniquePaths["OPTIONS"]
	if float64(unsafe404) >= t["method_404_min_count"] && float64(unsafeUnique) >= t["method_404_min_unique"] {
		signals = append(signals, signal("METHOD_404_SCAN", model.SignalBehavioral, map[string]any{
			"non_get_404": unsafe404, "distinct_method_path_pairs_at_least": unsafeUnique,
		}))
	}
	if float64(requests) >= t["missing_ua_min_requests"] && float64(snapshot.MissingUserAgent) >= t["missing_ua_min_count"] && ratio(snapshot.MissingUserAgent, requests) >= t["missing_ua_ratio"] {
		signals = append(signals, signal("MISSING_USER_AGENT", model.SignalSupporting, map[string]any{
			"missing": snapshot.MissingUserAgent, "requests": requests,
		}))
	}
	if float64(requests) >= t["ua_rotation_min_requests"] && float64(snapshot.UserAgents) >= t["ua_rotation_min_distinct"] && float64(snapshot.UserAgentSwitches) >= t["ua_rotation_min_switches"] {
		signals = append(signals, signal("USER_AGENT_ROTATION", model.SignalSupporting, map[string]any{
			"distinct_user_agents_at_least": snapshot.UserAgents, "switches": snapshot.UserAgentSwitches, "saturated": snapshot.Saturation.UserAgents,
		}))
	}
	for _, userAgent := range snapshot.UserAgentSamples {
		lower := strings.ToLower(userAgent)
		if strings.Contains(lower, "python-requests") || strings.Contains(lower, "curl/") || strings.Contains(lower, "wget/") || strings.Contains(lower, "scrapy") {
			signals = append(signals, signal("AUTOMATED_USER_AGENT", model.SignalSupporting, map[string]any{
				"user_agent": userAgent,
			}))
			break
		}
	}
	if snapshot.Saturation.Degraded {
		filtered := signals[:0]
		for _, item := range signals {
			switch item.Code {
			case "HIGH_404_DIVERSITY", "PATH_ENUMERATION", "QUERY_ENUMERATION", "METHOD_404_SCAN", "USER_AGENT_ROTATION", "AUTOMATED_USER_AGENT":
				continue
			}
			item.Evidence["degraded"] = true
			filtered = append(filtered, item)
		}
		return filtered
	}
	return signals
}

// NormalizePath replaces numeric path segments without altering other path
// components. Query value normalization happens in the bounded aggregator.
func NormalizePath(path string) string {
	path = aggregator.CanonicalPath(path)
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if numeric(part) {
			parts[i] = "{NUMBER}"
		}
	}
	return strings.Join(parts, "/")
}

func numeric(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func ratio(numerator, denominator uint64) float64 {
	if denominator == 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}

func signal(code string, strength model.SignalStrength, evidence map[string]any) model.Signal {
	return model.Signal{Code: code, Strength: strength, Evidence: evidence}
}
