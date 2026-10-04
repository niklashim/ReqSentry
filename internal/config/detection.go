package config

import (
	"fmt"
	"math"
	"strings"
)

type DetectionConfig struct {
	RulesetVersion  int                `yaml:"ruleset_version"`
	WatchScore      int                `yaml:"watch_score"`
	SuspiciousScore int                `yaml:"suspicious_score"`
	WouldBlockScore int                `yaml:"would_block_score"`
	ExcludedASNs    []uint32           `yaml:"excluded_asns"`
	Weights         map[string]int     `yaml:"weights"`
	Thresholds      map[string]float64 `yaml:"thresholds"`
}

// Prioritize scan behavior over automation or shared-address metadata. Query
// variation and resource impact retain small contextual weights; neither is
// proof of abusive intent. See docs/scoring.md for rationale and calibration.
var defaultWeights = map[string]int{
	"HIGH_404_RATE": 20, "HIGH_404_DIVERSITY": 25,
	"PATH_ENUMERATION": 25, "QUERY_ENUMERATION": 10,
	"HIGH_REQUEST_RATE": 15, "HIGH_BURST_RATE": 10, "SUSTAINED_HIGH_RATE": 15,
	"WORDPRESS_ENDPOINT_FLOOD": 30,
	"HIGH_5XX_CONTRIBUTION":    5, "HIGH_REDIRECT_RATIO": 0,
	"METHOD_404_SCAN": 20, "MISSING_USER_AGENT": 0,
	"USER_AGENT_ROTATION": 0, "AUTOMATED_USER_AGENT": 0,
	"HOSTING_NETWORK": 20,
	"CROSS_SITE_SCAN": 20, "HIGH_TRAFFIC_SHARE": 5,
	"CPU_SPIKE_CONTRIBUTOR": 5, "PHP_FPM_SATURATION_CONTRIBUTOR": 5,
	"HIGH_REQUEST_COST": 10,
}

var defaultThresholds = map[string]float64{
	"high_404_min_requests": 30, "high_404_min_count": 20, "high_404_ratio": 0.70,
	"unique_404_min": 20, "unique_404_ratio": 0.60,
	"path_enumeration_min": 10, "query_enumeration_min": 10,
	"high_rate_min_requests": 100, "high_rate_rps": 10, "burst_rps": 50,
	"sustained_rps": 10, "sustained_active_ratio": 0.80,
	"high_5xx_min_requests": 30, "high_5xx_min_count": 10, "high_5xx_ratio": 0.20,
	"redirect_min_requests": 30, "redirect_min_count": 20, "redirect_ratio": 0.70,
	"method_404_min_count": 10, "method_404_min_unique": 10,
	"missing_ua_min_requests": 20, "missing_ua_min_count": 15, "missing_ua_ratio": 0.70,
	"ua_rotation_min_requests": 20, "ua_rotation_min_distinct": 4, "ua_rotation_min_switches": 6,
	"cross_site_min_sites": 3, "cross_site_min_requests": 50,
	"cross_site_min_404_count": 30, "cross_site_404_ratio": 0.60, "cross_site_min_unique404": 20,
	"high_share_min_requests": 100, "high_share_ratio": 0.30,
	"cpu_pressure_percent": 80, "high_cost_min_samples": 10, "high_cost_ms": 500,
	"wordpress_min_requests": 100, "wordpress_rps": 10, "wordpress_active_ratio": 0.80,
}

func DefaultDetectionConfig() DetectionConfig {
	result := DetectionConfig{RulesetVersion: 2, WatchScore: 30, SuspiciousScore: 60, WouldBlockScore: 80,
		ExcludedASNs: []uint32{15169},
		Weights:      make(map[string]int, len(defaultWeights)), Thresholds: make(map[string]float64, len(defaultThresholds))}
	for key, value := range defaultWeights {
		result.Weights[key] = value
	}
	for key, value := range defaultThresholds {
		result.Thresholds[key] = value
	}
	return result
}

func (d *DetectionConfig) Validate() error {
	defaults := DefaultDetectionConfig()
	if d.RulesetVersion == 0 {
		d.RulesetVersion = defaults.RulesetVersion
	}
	if d.WatchScore == 0 {
		d.WatchScore = defaults.WatchScore
	}
	if d.SuspiciousScore == 0 {
		d.SuspiciousScore = defaults.SuspiciousScore
	}
	if d.WouldBlockScore == 0 {
		d.WouldBlockScore = defaults.WouldBlockScore
	}
	if d.ExcludedASNs == nil {
		d.ExcludedASNs = defaults.ExcludedASNs
	}
	if len(d.ExcludedASNs) > 64 {
		return fmt.Errorf("detection.excluded_asns supports at most 64 ASNs")
	}
	seenASNs := make(map[uint32]bool)
	for _, asn := range d.ExcludedASNs {
		if asn == 0 || seenASNs[asn] {
			return fmt.Errorf("detection.excluded_asns requires unique nonzero ASN numbers")
		}
		seenASNs[asn] = true
	}
	if d.RulesetVersion < 1 || d.WatchScore < 1 || d.WatchScore >= d.SuspiciousScore || d.SuspiciousScore >= d.WouldBlockScore || d.WouldBlockScore > 100 {
		return fmt.Errorf("detection ruleset version or decision score thresholds are invalid")
	}
	for code, weight := range d.Weights {
		if _, known := defaultWeights[code]; !known || weight < 0 || weight > 100 {
			return fmt.Errorf("detection.weights.%s is unknown or outside 0-100", code)
		}
		defaults.Weights[code] = weight
	}
	for name, value := range d.Thresholds {
		if _, known := defaultThresholds[name]; !known || math.IsNaN(value) || math.IsInf(value, 0) || value <= 0 {
			return fmt.Errorf("detection.thresholds.%s is unknown or invalid", name)
		}
		if strings.HasSuffix(name, "_ratio") && value > 1 {
			return fmt.Errorf("detection.thresholds.%s must be at most 1", name)
		}
		if name == "cpu_pressure_percent" && value > 100 {
			return fmt.Errorf("detection.thresholds.%s must be at most 100", name)
		}
		defaults.Thresholds[name] = value
	}
	d.Weights = defaults.Weights
	d.Thresholds = defaults.Thresholds
	return nil
}

// ExcludesASN applies only to resolved local metadata; nil is unknown, not safe.
func (d DetectionConfig) ExcludesASN(asn *uint32) bool {
	if asn == nil {
		return false
	}
	for _, excluded := range d.ExcludedASNs {
		if *asn == excluded {
			return true
		}
	}
	return false
}
