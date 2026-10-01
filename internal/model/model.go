package model

import (
	"context"
	"net/netip"
	"time"
)

// RequestEvent is the common input for Nginx and Apache parsers. Optional
// timing values are pointers so missing measurements cannot look like zero.
type RequestEvent struct {
	Timestamp      time.Time
	SiteID         string
	ClientIP       netip.Addr
	LogIP          netip.Addr
	PeerIP         netip.Addr
	ForwardedFor   string
	CFConnectingIP string
	XRealIP        string
	Host           string
	Method         string
	Path           string
	Query          string
	Status         int
	Bytes          *int64
	Referrer       *string
	UserAgent      *string
	Location       *string
	RequestTime    *time.Duration
	UpstreamTime   *time.Duration
}

type Decision string

const (
	DecisionNormal     Decision = "NORMAL"
	DecisionWatch      Decision = "WATCH"
	DecisionSuspicious Decision = "SUSPICIOUS"
	DecisionWouldBlock Decision = "WOULD_BLOCK"
)

type Signal struct {
	Code     string         `json:"code"`
	Strength SignalStrength `json:"strength"`
	Weight   int            `json:"weight"`
	Evidence map[string]any `json:"evidence"`
}

type SignalStrength string

const (
	SignalSupporting SignalStrength = "supporting"
	SignalBehavioral SignalStrength = "behavioral"
	SignalStrong     SignalStrength = "strong"
)

// Incident is shared by persistence, local logs, and optional notifications.
// A decision is informational in V1; it is not an enforcement command.
type Incident struct {
	Timestamp            time.Time         `json:"timestamp"`
	Server               string            `json:"server"`
	SiteID               string            `json:"site_id"`
	ClientIP             netip.Addr        `json:"client_ip"`
	WindowStart          time.Time         `json:"window_start"`
	WindowEnd            time.Time         `json:"window_end"`
	Signals              []Signal          `json:"signals"`
	RawScore             int               `json:"raw_score"`
	Score                int               `json:"score"`
	Decision             Decision          `json:"decision"`
	RulesetVersion       int               `json:"ruleset_version"`
	MonitorOnly          bool              `json:"monitor_only"`
	Requests             uint64            `json:"requests"`
	PeakRPS              uint64            `json:"peak_rps"`
	BytesTotal           uint64            `json:"bytes_total"`
	BytesSamples         uint64            `json:"bytes_samples"`
	RequestTimeSamples   uint64            `json:"request_time_samples"`
	AverageRequestMS     *float64          `json:"average_request_ms,omitempty"`
	UpstreamTimeSamples  uint64            `json:"upstream_time_samples"`
	AverageUpstreamMS    *float64          `json:"average_upstream_ms,omitempty"`
	StatusFamilies       [6]uint64         `json:"status_families"`
	StatusCounts         map[int]uint64    `json:"status_counts"`
	MethodCounts         map[string]uint64 `json:"method_counts"`
	UniquePaths          int               `json:"unique_paths"`
	Unique404Paths       int               `json:"unique_404_paths"`
	EvidenceDegraded     bool              `json:"evidence_degraded"`
	EvidenceIncomplete   []string          `json:"evidence_incomplete,omitempty"`
	TrafficShare         *float64          `json:"traffic_share,omitempty"`
	TrafficShareCoverage string            `json:"traffic_share_coverage,omitempty"`
	HealthSampledAt      *time.Time        `json:"health_sampled_at,omitempty"`
	CPUPercent           *float64          `json:"cpu_percent,omitempty"`
	Load1                *float64          `json:"load_1,omitempty"`
	MemoryUsedPercent    *float64          `json:"memory_used_percent,omitempty"`
	PHPFPM               []PHPFPMEvidence  `json:"php_fpm,omitempty"`
	ASN                  *uint32           `json:"asn,omitempty"`
	ASNOrganization      string            `json:"asn_organization,omitempty"`
	ISP                  string            `json:"isp,omitempty"`
	NetworkType          string            `json:"network_type,omitempty"`
	Country              string            `json:"country,omitempty"`
	EnrichmentStatus     string            `json:"enrichment_status"`
}

type PHPFPMEvidence struct {
	Name               string    `json:"name"`
	SampledAt          time.Time `json:"sampled_at"`
	Stale              bool      `json:"stale"`
	ActiveProcesses    *int64    `json:"active_processes,omitempty"`
	IdleProcesses      *int64    `json:"idle_processes,omitempty"`
	TotalProcesses     *int64    `json:"total_processes,omitempty"`
	MaxActiveProcesses *int64    `json:"max_active_processes,omitempty"`
	MaxChildrenReached *int64    `json:"max_children_reached,omitempty"`
	SlowRequests       *int64    `json:"slow_requests,omitempty"`
	ListenQueue        *int64    `json:"listen_queue,omitempty"`
}

type IncidentSink interface {
	WriteIncident(context.Context, Incident) error
}
