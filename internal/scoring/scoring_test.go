package scoring

import (
	"net/netip"
	"testing"
	"time"

	"github.com/niklashim/ReqSentry/internal/aggregator"
	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
	"github.com/niklashim/ReqSentry/internal/serverhealth"
)

func testInput(signals ...model.Signal) Input {
	now := time.Unix(1_800_000_000, 0)
	return Input{
		Server: "web-prod", AllRequests: 200, Signals: signals,
		Snapshot: aggregator.Snapshot{
			At: now, Window: 30 * time.Second, SiteID: "shop", ClientIP: netip.MustParseAddr("2001:db8::1"),
			Requests: 100, PeakRPS: 20, ImportantStatuses: map[int]uint64{404: 80}, Methods: map[string]uint64{"GET": 100},
		},
	}
}

func TestSupportingSignalsCannotCreateWouldBlock(t *testing.T) {
	rules := config.DefaultDetectionConfig()
	rules.Weights["HIGH_REDIRECT_RATIO"] = 100
	engine, err := New(rules)
	if err != nil {
		t.Fatal(err)
	}
	incident := engine.Evaluate(testInput(model.Signal{Code: "HIGH_REDIRECT_RATIO", Strength: model.SignalSupporting, Evidence: map[string]any{"redirects": 80}}))
	if incident.Score != 100 || incident.Decision != model.DecisionSuspicious || !incident.MonitorOnly {
		t.Fatalf("supporting-only incident: %+v", incident)
	}
	if incident.Signals[0].Weight != 100 || incident.Signals[0].Evidence["redirects"] != 80 || incident.TrafficShare == nil || *incident.TrafficShare != 0.5 {
		t.Fatalf("incident evidence missing: %+v", incident)
	}
}

func TestSamplesDoNotChangeDecisionOrIdentityAndRemainImmutable(t *testing.T) {
	engine, err := New(config.DefaultDetectionConfig())
	if err != nil {
		t.Fatal(err)
	}
	input := testInput(model.Signal{Code: "PATH_ENUMERATION", Strength: model.SignalStrong})
	before := engine.Evaluate(input)
	bytes := int64(123)
	input.Snapshot.RequestSamples = []model.RequestSample{{Timestamp: input.Snapshot.At, SiteID: "shop", ClientIP: input.Snapshot.ClientIP, Method: "GET", Path: "/missing", Status: 404, Bytes: &bytes}}
	after := engine.Evaluate(input)
	if before.Score != after.Score || before.Decision != after.Decision || before.EventID != after.EventID || before.RawScore != after.RawScore {
		t.Fatal("request samples affected scoring")
	}
	bytes = 999
	input.Snapshot.RequestSamples[0].Path = "changed"
	if after.RequestSamples[0].Path != "/missing" || *after.RequestSamples[0].Bytes != 123 {
		t.Fatal("caller mutated saved evidence")
	}
}

func TestHostingMetadataCannotCreateWouldBlock(t *testing.T) {
	rules := config.DefaultDetectionConfig()
	rules.Weights["HOSTING_NETWORK"] = 100
	engine, err := New(rules)
	if err != nil {
		t.Fatal(err)
	}
	incident := engine.Evaluate(testInput(model.Signal{Code: "HOSTING_NETWORK", Strength: model.SignalSupporting, Evidence: map[string]any{"network_type": "hosting"}}))
	if incident.Decision == model.DecisionWouldBlock {
		t.Fatalf("hosting metadata alone triggered hypothetical enforcement: %+v", incident)
	}
}

func TestStrongOrIndependentBehaviorGate(t *testing.T) {
	rules := config.DefaultDetectionConfig()
	rules.RulesetVersion = 3
	rules.Weights["PATH_ENUMERATION"] = 80
	rules.Weights["HIGH_REQUEST_RATE"] = 50
	rules.Weights["HIGH_BURST_RATE"] = 50
	rules.Weights["METHOD_404_SCAN"] = 50
	engine, err := New(rules)
	if err != nil {
		t.Fatal(err)
	}
	strong := engine.Evaluate(testInput(model.Signal{Code: "PATH_ENUMERATION", Strength: model.SignalStrong}))
	if strong.Decision != model.DecisionWouldBlock || strong.RulesetVersion != 3 {
		t.Fatalf("strong signal decision: %+v", strong)
	}
	correlated := engine.Evaluate(testInput(
		model.Signal{Code: "HIGH_REQUEST_RATE", Strength: model.SignalBehavioral},
		model.Signal{Code: "HIGH_BURST_RATE", Strength: model.SignalBehavioral},
	))
	if correlated.Decision != model.DecisionSuspicious || correlated.Score != 100 {
		t.Fatalf("one behavior group should not pass gate: %+v", correlated)
	}
	independent := engine.Evaluate(testInput(
		model.Signal{Code: "HIGH_REQUEST_RATE", Strength: model.SignalBehavioral},
		model.Signal{Code: "METHOD_404_SCAN", Strength: model.SignalBehavioral},
	))
	if independent.Decision != model.DecisionWouldBlock {
		t.Fatalf("independent behavior groups should pass: %+v", independent)
	}
	duplicate := engine.Evaluate(testInput(
		model.Signal{Code: "HIGH_REQUEST_RATE", Strength: model.SignalBehavioral},
		model.Signal{Code: "HIGH_REQUEST_RATE", Strength: model.SignalBehavioral},
	))
	if duplicate.RawScore != 50 || duplicate.Signals[1].Weight != 0 {
		t.Fatalf("duplicate reason inflated score: %+v", duplicate)
	}
}

func TestHealthMustBeTimeAligned(t *testing.T) {
	engine, err := New(config.DefaultDetectionConfig())
	if err != nil {
		t.Fatal(err)
	}
	input := testInput()
	cpu := 90.0
	input.Health = serverhealth.Snapshot{Timestamp: input.Snapshot.At.Add(-time.Minute), CPUPercent: &cpu}
	stale := engine.Evaluate(input)
	if stale.CPUPercent != nil {
		t.Fatal("stale CPU entered incident")
	}
	input.Health.Timestamp = input.Snapshot.At
	fresh := engine.Evaluate(input)
	if fresh.CPUPercent == nil || *fresh.CPUPercent != 90 {
		t.Fatal("fresh CPU missing")
	}
	if fresh.HealthSampledAt == nil || !fresh.HealthSampledAt.Equal(input.Snapshot.At) || fresh.TrafficShareCoverage != "configured access logs only" {
		t.Fatalf("health timestamp or traffic coverage missing: %+v", fresh)
	}
}

func TestIncidentKeepsAvailableTimingAndBytes(t *testing.T) {
	engine, err := New(config.DefaultDetectionConfig())
	if err != nil {
		t.Fatal(err)
	}
	input := testInput(model.Signal{Code: "HIGH_REQUEST_COST", Strength: model.SignalBehavioral})
	input.Snapshot.RequestTimeSamples = 2
	input.Snapshot.RequestTimeNanos = uint64(1500 * time.Millisecond)
	input.Snapshot.UpstreamTimeSamples = 1
	input.Snapshot.UpstreamTimeNanos = uint64(300 * time.Millisecond)
	input.Snapshot.BytesSamples = 2
	input.Snapshot.BytesTotal = 4096
	incident := engine.Evaluate(input)
	if incident.AverageRequestMS == nil || *incident.AverageRequestMS != 750 || incident.AverageUpstreamMS == nil || *incident.AverageUpstreamMS != 300 || incident.BytesTotal != 4096 {
		t.Fatalf("timing or byte evidence lost: %+v", incident)
	}
}
