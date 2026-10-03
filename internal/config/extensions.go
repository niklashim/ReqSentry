package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

type LogProfile struct {
	Preset       string            `yaml:"preset"`
	Fields       map[string]string `yaml:"fields"`
	Timestamp    string            `yaml:"timestamp"`
	DurationUnit string            `yaml:"duration_unit"`
}
type CorrelationConfig struct {
	Window    Duration `yaml:"window"`
	MaxEvents int      `yaml:"max_events"`
}
type RecoveryConfig struct {
	Enabled  bool     `yaml:"enabled"`
	Interval Duration `yaml:"interval"`
	MaxBytes int64    `yaml:"max_bytes"`
}
type RetentionConfig struct {
	MaxAge                Duration `yaml:"max_age"`
	Incidents             Duration `yaml:"incidents"`
	Errors                Duration `yaml:"errors"`
	Minutes               Duration `yaml:"minutes"`
	Interval              Duration `yaml:"interval"`
	ErrorSamplesPerSecond int      `yaml:"error_samples_per_second"`
	BatchSize             int      `yaml:"batch_size"`
	MinimumFreeBytes      uint64   `yaml:"minimum_free_bytes"`
}
type DestinationConfig struct {
	Name              string   `yaml:"name"`
	Type              string   `yaml:"type"`
	Enabled           bool     `yaml:"enabled"`
	WebhookEnv        string   `yaml:"webhook_env"`
	WebhookCredential string   `yaml:"webhook_credential"`
	TopicARN          string   `yaml:"topic_arn"`
	Region            string   `yaml:"region"`
	Profile           string   `yaml:"aws_profile"`
	Sites             []string `yaml:"sites"`
	Decisions         []string `yaml:"decisions"`
	MinimumScore      int      `yaml:"minimum_score"`
	Operational       bool     `yaml:"operational"`
	Cooldown          Duration `yaml:"cooldown"`
	QueueSize         int      `yaml:"queue_size"`
	MaxAttempts       int      `yaml:"max_attempts"`
	MaxAge            Duration `yaml:"max_age"`
	DashboardURL      string   `yaml:"dashboard_url"`
}

var LogFields = strings.Fields("timestamp client_ip peer xff cfip xrealip method target path query status bytes host user_agent referrer request_time upstream_time location request_id trace_id severity message error_type error_code stack_trace")

func (c *Config) validateExtensions() error {
	for name, p := range c.LogProfiles {
		if name == "" || len(name) > 128 {
			return fmt.Errorf("invalid log profile name")
		}
		if p.Preset != "" && p.Preset != "canonical" && p.Preset != "ecs" && p.Preset != "ecs-v1" {
			return fmt.Errorf("log profile %s: unsupported preset", name)
		}
		if p.Timestamp != "" && p.Timestamp != "rfc3339" && p.Timestamp != "unix_s" && p.Timestamp != "unix_ms" && p.Timestamp != "unix_ns" {
			return fmt.Errorf("log profile %s: unsupported timestamp encoding", name)
		}
		if p.DurationUnit != "" && p.DurationUnit != "s" && p.DurationUnit != "ms" && p.DurationUnit != "us" && p.DurationUnit != "ns" {
			return fmt.Errorf("log profile %s: invalid duration unit", name)
		}
		selectors := map[string]bool{}
		for target, selector := range p.Fields {
			valid := false
			for _, field := range LogFields {
				if target == field {
					valid = true
				}
			}
			if !valid || selector == "" || len(selector) > 256 || selectors[selector] {
				return fmt.Errorf("log profile %s: unknown field or conflicting selector", name)
			}
			selectors[selector] = true
			if strings.HasPrefix(selector, "/") {
				for _, part := range strings.Split(selector[1:], "/") {
					if part == "" {
						return fmt.Errorf("log profile %s: empty selector segment", name)
					}
				}
			}
		}
	}
	paths := map[string]bool{}
	validateSource := func(a *AccessFile, kind string) error {
		if err := absolutePath("log source path", a.Path); err != nil {
			return err
		}
		if paths[a.Path] {
			return fmt.Errorf("duplicate log source path %q", a.Path)
		}
		paths[a.Path] = true
		a.Kind = kind
		if a.Format == "" {
			if kind == "error" {
				a.Format = a.Type + "-error"
			} else {
				a.Format = "combined"
			}
		}
		switch a.Format {
		case "combined", "json", "logfmt":
		case "nginx-error", "apache-error":
			if kind != "error" {
				return fmt.Errorf("error format requires an error source")
			}
		default:
			return fmt.Errorf("unsupported log format %q", a.Format)
		}
		if kind == "error" && a.Format == "combined" {
			return fmt.Errorf("error source requires an error format")
		}
		if a.Profile != "" {
			if _, ok := c.LogProfiles[a.Profile]; !ok {
				return fmt.Errorf("unknown log profile %q", a.Profile)
			}
			if a.Format != "json" && a.Format != "logfmt" {
				return fmt.Errorf("profiles require structured format")
			}
		}
		if a.Timezone == "" {
			a.Timezone = "UTC"
		}
		if _, err := time.LoadLocation(a.Timezone); err != nil {
			return fmt.Errorf("invalid source timezone")
		}
		if len(a.Site) > 128 || len(a.Path) > 4096 {
			return fmt.Errorf("source identity exceeds limits")
		}
		if a.RetainStackTrace && kind != "error" {
			return fmt.Errorf("retain_stack_trace requires an error source")
		}
		if kind == "error" && a.MinimumSeverity == "" {
			a.MinimumSeverity = "warning"
		}
		if a.MinimumSeverity != "" {
			switch a.MinimumSeverity {
			case "debug", "info", "notice", "warning", "error", "critical", "alert", "emergency":
			default:
				return fmt.Errorf("invalid minimum severity")
			}
		}
		return nil
	}
	if len(c.ErrorFiles) > 128 || len(c.LogProfiles) > 128 {
		return fmt.Errorf("at most 128 error sources and log profiles supported")
	}
	for i := range c.AccessFiles {
		if err := validateSource(&c.AccessFiles[i], "access"); err != nil {
			return err
		}
	}
	for i := range c.ErrorFiles {
		if err := validateSource(&c.ErrorFiles[i], "error"); err != nil {
			return err
		}
	}
	if c.Correlation.Window.Duration == 0 {
		c.Correlation.Window.Duration = time.Minute
	}
	if c.Correlation.Window.Duration < time.Second || c.Correlation.Window.Duration > 5*time.Minute {
		return fmt.Errorf("correlation.window must be 1s to 5m")
	}
	if c.Correlation.MaxEvents == 0 {
		c.Correlation.MaxEvents = 4096
	}
	if c.Correlation.MaxEvents < 32 || c.Correlation.MaxEvents > 16384 {
		return fmt.Errorf("correlation.max_events must be 32 to 16384")
	}
	r := &c.Database.Retention
	if r.MaxAge.Duration == 0 {
		r.MaxAge.Duration = 4 * 24 * time.Hour
	}
	if r.MaxAge.Duration < time.Hour {
		return fmt.Errorf("retention.max_age must be at least one hour")
	}
	if r.ErrorSamplesPerSecond == 0 {
		r.ErrorSamplesPerSecond = 20
	}
	if r.ErrorSamplesPerSecond < 1 || r.ErrorSamplesPerSecond > 1000 {
		return fmt.Errorf("error_samples_per_second must be 1 to 1000")
	}
	if r.Incidents.Duration < 0 || r.Errors.Duration < 0 || r.Minutes.Duration < 0 {
		return fmt.Errorf("invalid retention limits")
	}
	*r = r.Effective()
	if r.Interval.Duration == 0 {
		r.Interval.Duration = time.Minute
	}
	if r.BatchSize == 0 {
		r.BatchSize = 500
	}
	if r.Incidents.Duration < 0 || r.Errors.Duration < time.Hour || r.Minutes.Duration < time.Hour || r.Interval.Duration < time.Second || r.BatchSize < 1 || r.BatchSize > 2000 {
		return fmt.Errorf("invalid retention limits")
	}
	if c.Recovery.Enabled && c.Trigger.Mode != "always" {
		return fmt.Errorf("recovery currently requires trigger.mode: always")
	}
	if c.Recovery.Interval.Duration == 0 {
		c.Recovery.Interval.Duration = time.Minute
	}
	if c.Recovery.MaxBytes == 0 {
		c.Recovery.MaxBytes = 16 << 20
	}
	if c.Recovery.Interval.Duration < time.Second || c.Recovery.MaxBytes < 1<<20 || c.Recovery.MaxBytes > 128<<20 {
		return fmt.Errorf("invalid recovery limits")
	}
	names := map[string]bool{}
	if len(c.Output.Destinations) > 32 {
		return fmt.Errorf("at most 32 notification destinations")
	}
	for i := range c.Output.Destinations {
		d := &c.Output.Destinations[i]
		if d.Name == "" || len(d.Name) > 80 || names[d.Name] {
			return fmt.Errorf("destination names must be unique and nonempty")
		}
		names[d.Name] = true
		if d.Type != "slack" && d.Type != "teams" && d.Type != "sns" {
			return fmt.Errorf("unsupported destination type")
		}
		if d.Enabled && d.Type == "slack" && c.Output.Slack.Enabled {
			return fmt.Errorf("use legacy output.slack or named Slack destinations, not both")
		}
		if d.Enabled {
			if d.Type == "sns" {
				parts := strings.Split(d.TopicARN, ":")
				if len(parts) != 6 || parts[0] != "arn" || parts[2] != "sns" || parts[3] != d.Region || parts[4] == "" || parts[5] == "" || strings.HasSuffix(parts[5], ".fifo") {
					return fmt.Errorf("SNS requires a standard topic ARN matching its region")
				}
			} else if err := validateSecretRef("destination webhook", d.WebhookEnv, d.WebhookCredential); err != nil {
				return err
			}
		}
		if d.MinimumScore < 0 || d.MinimumScore > 100 {
			return fmt.Errorf("destination minimum_score must be 0 to 100")
		}
		for _, v := range d.Decisions {
			if v != "WATCH" && v != "SUSPICIOUS" && v != "WOULD_BLOCK" {
				return fmt.Errorf("invalid destination decision")
			}
		}
		if d.Cooldown.Duration == 0 {
			d.Cooldown.Duration = 10 * time.Minute
		}
		if d.QueueSize == 0 {
			d.QueueSize = 128
		}
		if d.MaxAttempts == 0 {
			d.MaxAttempts = 3
		}
		if d.MaxAge.Duration == 0 {
			d.MaxAge.Duration = time.Minute
		}
		if d.Cooldown.Duration < 0 || d.QueueSize < 1 || d.QueueSize > 1024 || d.MaxAttempts < 1 || d.MaxAttempts > 8 || d.MaxAge.Duration < time.Second || d.MaxAge.Duration > time.Hour {
			return fmt.Errorf("invalid notification queue/retry limits")
		}
		if d.DashboardURL != "" {
			u, err := url.Parse(d.DashboardURL)
			if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
				return fmt.Errorf("dashboard_url must be a public HTTPS base URL")
			}
		}
	}
	return nil
}

// Effective applies one ceiling to all saved investigation history. Legacy
// per-table settings may shorten retention but cannot disable the ceiling.
func (r RetentionConfig) Effective() RetentionConfig {
	if r.MaxAge.Duration == 0 {
		r.MaxAge.Duration = 4 * 24 * time.Hour
	}
	for _, v := range []*Duration{&r.Incidents, &r.Errors, &r.Minutes} {
		if v.Duration == 0 || v.Duration > r.MaxAge.Duration {
			v.Duration = r.MaxAge.Duration
		}
	}
	if r.Interval.Duration == 0 {
		r.Interval.Duration = time.Minute
	}
	if r.BatchSize == 0 {
		r.BatchSize = 500
	}
	return r
}
