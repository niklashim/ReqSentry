package detector

import (
	"time"

	"github.com/niklashim/ReqSentry/internal/aggregator"
	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
	"github.com/niklashim/ReqSentry/internal/phpfpm"
	"github.com/niklashim/ReqSentry/internal/serverhealth"
)

// Impact correlates a server-wide IP window with all observed traffic and
// nearby health samples. Its evidence explicitly avoids claiming causality.
func Impact(global aggregator.Snapshot, allRequests uint64, siteCount int, health serverhealth.Snapshot, pools []phpfpm.State) []model.Signal {
	return ImpactWithRules(global, allRequests, siteCount, health, pools, config.DefaultDetectionConfig())
}

func ImpactWithRules(global aggregator.Snapshot, allRequests uint64, siteCount int, health serverhealth.Snapshot, pools []phpfpm.State, rules config.DetectionConfig) []model.Signal {
	t := thresholds(rules)
	var signals []model.Signal
	if global.SiteID != "" || global.Requests == 0 {
		return signals
	}
	notFound := global.ImportantStatuses[404]
	if float64(siteCount) >= t["cross_site_min_sites"] && float64(global.Requests) >= t["cross_site_min_requests"] && float64(notFound) >= t["cross_site_min_404_count"] && ratio(notFound, global.Requests) >= t["cross_site_404_ratio"] && float64(global.Unique404Paths) >= t["cross_site_min_unique404"] {
		signals = append(signals, signal("CROSS_SITE_SCAN", model.SignalBehavioral, map[string]any{
			"sites": siteCount, "requests": global.Requests, "status_404": notFound,
		}))
	}
	share := ratio(global.Requests, allRequests)
	if float64(global.Requests) >= t["high_share_min_requests"] && share >= t["high_share_ratio"] {
		signals = append(signals, signal("HIGH_TRAFFIC_SHARE", model.SignalBehavioral, map[string]any{
			"requests": global.Requests, "observed_server_requests": allRequests,
			"share": share, "coverage": "configured access logs only",
		}))
	}
	if float64(global.Requests) >= t["high_share_min_requests"] && share >= t["high_share_ratio"] && health.CPUPercent != nil && aligned(global.At, health.Timestamp, 5*time.Second) && *health.CPUPercent >= t["cpu_pressure_percent"] {
		signals = append(signals, signal("CPU_SPIKE_CONTRIBUTOR", model.SignalBehavioral, map[string]any{
			"cpu_percent": *health.CPUPercent, "traffic_share": share,
			"relationship": "time-aligned correlation, not proven causation",
		}))
	}
	if float64(global.Requests) >= t["high_share_min_requests"] && share >= t["high_share_ratio"] {
		for _, pool := range pools {
			if pool.Stale || pool.Stats == nil || pool.Stats.ListenQueue == nil || *pool.Stats.ListenQueue == 0 || !aligned(global.At, pool.SampledAt, 10*time.Second) {
				continue
			}
			signals = append(signals, signal("PHP_FPM_SATURATION_CONTRIBUTOR", model.SignalBehavioral, map[string]any{
				"pool": pool.Name, "listen_queue": *pool.Stats.ListenQueue,
				"traffic_share": share, "relationship": "time-aligned correlation, not proven causation",
			}))
		}
	}
	if float64(global.RequestTimeSamples) >= t["high_cost_min_samples"] && global.Requests >= 10 && share >= 0.10 {
		averageNanos := global.RequestTimeNanos / global.RequestTimeSamples
		if float64(averageNanos)/float64(time.Millisecond) >= t["high_cost_ms"] {
			signals = append(signals, signal("HIGH_REQUEST_COST", model.SignalBehavioral, map[string]any{
				"average_request_ms": float64(averageNanos) / float64(time.Millisecond),
				"timed_requests":     global.RequestTimeSamples, "traffic_share": share,
			}))
		}
	}
	return signals
}

func aligned(reference, sample time.Time, tolerance time.Duration) bool {
	if reference.IsZero() || sample.IsZero() {
		return false
	}
	delta := reference.Sub(sample)
	if delta < 0 {
		delta = -delta
	}
	return delta <= tolerance
}
