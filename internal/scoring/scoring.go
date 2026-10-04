// Package scoring turns deterministic signals into versioned monitor-only
// incidents. It does not perform network actions or depend on an enforcer.
package scoring

import (
	"fmt"
	"strings"
	"time"

	"github.com/niklashim/ReqSentry/internal/aggregator"
	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/enrichment"
	"github.com/niklashim/ReqSentry/internal/model"
	"github.com/niklashim/ReqSentry/internal/phpfpm"
	"github.com/niklashim/ReqSentry/internal/serverhealth"
)

type Engine struct {
	rules config.DetectionConfig
}

type Input struct {
	Server           string
	Snapshot         aggregator.Snapshot
	Signals          []model.Signal
	AllRequests      uint64
	Health           serverhealth.Snapshot
	PHPFPM           []phpfpm.State
	Enrichment       enrichment.Result
	EnrichmentStatus string
}

func New(rules config.DetectionConfig) (*Engine, error) {
	if err := rules.Validate(); err != nil {
		return nil, err
	}
	return &Engine{rules: rules}, nil
}

func (e *Engine) Evaluate(input Input) model.Incident {
	snapshot := input.Snapshot
	incident := model.Incident{
		RequestSamples: model.CloneRequestSamples(snapshot.RequestSamples),
		Timestamp:      snapshot.At, Server: input.Server, SiteID: snapshot.SiteID,
		ClientIP: snapshot.ClientIP, WindowStart: snapshot.At.Add(-snapshot.Window), WindowEnd: snapshot.At,
		Decision: model.DecisionNormal, RulesetVersion: e.rules.RulesetVersion, MonitorOnly: true,
		Requests: snapshot.Requests, PeakRPS: snapshot.PeakRPS,
		BytesTotal: snapshot.BytesTotal, BytesSamples: snapshot.BytesSamples,
		RequestTimeSamples: snapshot.RequestTimeSamples, UpstreamTimeSamples: snapshot.UpstreamTimeSamples,
		StatusFamilies: snapshot.StatusFamilies, StatusCounts: cloneCounts(snapshot.ImportantStatuses),
		MethodCounts: cloneMethodCounts(snapshot.Methods), UniquePaths: snapshot.UniquePaths,
		Unique404Paths:   snapshot.Unique404Paths,
		EvidenceDegraded: snapshot.Saturation.Degraded,
	}
	incident.EnrichmentStatus = input.EnrichmentStatus
	if incident.EnrichmentStatus == "" {
		incident.EnrichmentStatus = "disabled"
	}
	geo := input.Enrichment
	incident.ASN, incident.ASNOrganization, incident.ISP = geo.ASN, geo.ASNOrganization, geo.ISP
	incident.NetworkType, incident.Country = geo.NetworkType, geo.Country
	if geo.Available && geo.Found && e.rules.ExcludesASN(geo.ASN) {
		incident.EnsureEventID()
		return incident
	}
	for _, item := range []struct {
		name       string
		incomplete bool
	}{
		{"paths", snapshot.Saturation.Paths || snapshot.Saturation.Degraded},
		{"missing_paths", snapshot.Saturation.MissingPaths || snapshot.Saturation.Degraded},
		{"user_agents", snapshot.Saturation.UserAgents || snapshot.Saturation.Degraded},
		{"query_patterns", snapshot.Saturation.QueryPatterns || snapshot.Saturation.Degraded},
		{"query_values", snapshot.Saturation.QueryValues || snapshot.Saturation.Degraded},
		{"active_records", snapshot.Saturation.RecordLimit},
	} {
		if item.incomplete {
			incident.EvidenceIncomplete = append(incident.EvidenceIncomplete, item.name)
		}
	}
	if snapshot.RequestTimeSamples > 0 {
		value := float64(snapshot.RequestTimeNanos) / float64(snapshot.RequestTimeSamples) / float64(time.Millisecond)
		incident.AverageRequestMS = &value
	}
	if snapshot.UpstreamTimeSamples > 0 {
		value := float64(snapshot.UpstreamTimeNanos) / float64(snapshot.UpstreamTimeSamples) / float64(time.Millisecond)
		incident.AverageUpstreamMS = &value
	}
	if input.AllRequests > 0 {
		share := float64(snapshot.Requests) / float64(input.AllRequests)
		incident.TrafficShare = &share
		incident.TrafficShareCoverage = "configured access logs only"
	}
	if aligned(snapshot.At, input.Health.Timestamp, 5*time.Second) {
		at := input.Health.Timestamp
		incident.HealthSampledAt = &at
		incident.CPUPercent = input.Health.CPUPercent
		incident.Load1 = input.Health.Load1
		incident.MemoryUsedPercent = input.Health.MemoryUsedPercent
	}
	for _, state := range input.PHPFPM {
		if state.Stats == nil || !aligned(snapshot.At, state.SampledAt, 10*time.Second) {
			continue
		}
		incident.PHPFPM = append(incident.PHPFPM, model.PHPFPMEvidence{
			Name: state.Name, SampledAt: state.SampledAt, Stale: state.Stale,
			ActiveProcesses: state.Stats.ActiveProcesses, IdleProcesses: state.Stats.IdleProcesses,
			TotalProcesses: state.Stats.TotalProcesses, MaxActiveProcesses: state.Stats.MaxActiveProcesses,
			MaxChildrenReached: state.Stats.MaxChildrenReached, SlowRequests: state.Stats.SlowRequests,
			ListenQueue: state.Stats.ListenQueue,
		})
	}
	seen := make(map[string]bool)
	groups := make(map[string]bool)
	strong := false
	signals := append([]model.Signal(nil), input.Signals...)
	if geo.Available && geo.Found && strings.EqualFold(geo.NetworkType, "hosting") {
		signals = append(signals, model.Signal{Code: "HOSTING_NETWORK", Strength: model.SignalSupporting, Evidence: map[string]any{"network_type": geo.NetworkType}})
	}
	for _, original := range signals {
		signal := original
		if !seen[signal.Code] {
			signal.Weight = e.rules.Weights[signal.Code]
			seen[signal.Code] = true
			incident.RawScore += signal.Weight
			if signal.Weight > 0 && signal.Strength == model.SignalStrong {
				strong = true
			}
			if signal.Weight > 0 && signal.Strength == model.SignalBehavioral {
				groups[behaviorGroup(signal.Code)] = true
			}
		}
		incident.Signals = append(incident.Signals, signal)
	}
	incident.Score = incident.RawScore
	if incident.Score > 100 {
		incident.Score = 100
	}
	switch {
	case incident.Score >= e.rules.WouldBlockScore && (strong || len(groups) >= 2):
		incident.Decision = model.DecisionWouldBlock
	case incident.Score >= e.rules.SuspiciousScore:
		incident.Decision = model.DecisionSuspicious
	case incident.Score >= e.rules.WatchScore:
		incident.Decision = model.DecisionWatch
	}
	incident.EnsureEventID()
	return incident
}

func behaviorGroup(code string) string {
	switch code {
	case "HIGH_REQUEST_RATE", "HIGH_BURST_RATE", "SUSTAINED_HIGH_RATE":
		return "rate"
	case "METHOD_404_SCAN":
		return "methods"
	case "CROSS_SITE_SCAN":
		return "cross_site"
	default:
		return fmt.Sprintf("other:%s", code)
	}
}

func cloneCounts(values map[int]uint64) map[int]uint64 {
	result := make(map[int]uint64, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func cloneMethodCounts(values map[string]uint64) map[string]uint64 {
	result := make(map[string]uint64, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
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
