package config

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const DefaultPath = "/etc/reqsentry/config.yaml"

var environmentName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var credentialName = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// Duration accepts the same units as time.ParseDuration in YAML.
type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return errors.New("duration must be a string such as 30s")
	}
	parsed, err := time.ParseDuration(node.Value)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", node.Value, err)
	}
	d.Duration = parsed
	return nil
}

type AccessFile struct {
	Path string `yaml:"path"`
	Site string `yaml:"site"`
	Type string `yaml:"type"`
}

// Access files may use the paths in the original brief or an explicit mapping.
func (a *AccessFile) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		a.Path = node.Value
	case yaml.MappingNode:
		seen := make(map[string]bool)
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i].Value
			value := node.Content[i+1]
			if seen[key] {
				return fmt.Errorf("duplicate access file field %q", key)
			}
			seen[key] = true
			if value.Kind != yaml.ScalarNode {
				return fmt.Errorf("access file %s must be a string", key)
			}
			switch key {
			case "path":
				a.Path = value.Value
			case "site":
				a.Site = value.Value
			case "type":
				a.Type = value.Value
			default:
				return fmt.Errorf("unknown access file field %q", key)
			}
		}
	default:
		return errors.New("access file must be a path or mapping")
	}
	return nil
}

type Config struct {
	Server      ServerConfig      `yaml:"server"`
	Mode        string            `yaml:"mode"`
	AccessFiles []AccessFile      `yaml:"access_files"`
	ClientIP    ClientIPConfig    `yaml:"client_ip"`
	Allowlist   []string          `yaml:"allowlist"`
	Trigger     TriggerConfig     `yaml:"trigger"`
	Analysis    AnalysisConfig    `yaml:"analysis"`
	Aggregation AggregationConfig `yaml:"aggregation"`
	Health      HealthConfig      `yaml:"health"`
	PHPFPM      PHPFPMConfig      `yaml:"php_fpm"`
	Detection   DetectionConfig   `yaml:"detection"`
	Database    DatabaseConfig    `yaml:"database"`
	MaxMind     MaxMindConfig     `yaml:"maxmind"`
	Output      OutputConfig      `yaml:"output"`
}

type ServerConfig struct {
	Name string `yaml:"name"`
}

type ClientIPConfig struct {
	Header         string   `yaml:"header"`
	TrustedProxies []string `yaml:"trusted_proxies"`
}

type TriggerConfig struct {
	Mode          string   `yaml:"mode"`
	CPUStart      float64  `yaml:"cpu_start"`
	CPUStop       float64  `yaml:"cpu_stop"`
	StartDuration Duration `yaml:"start_duration"`
	StopDuration  Duration `yaml:"stop_duration"`
}

type AnalysisConfig struct {
	Window Duration `yaml:"window"`
}

type AggregationConfig struct {
	MaxActiveRecords   int   `yaml:"max_active_records"`
	MaxPathsPerIP      int   `yaml:"max_paths_per_ip"`
	Max404PathsPerIP   int   `yaml:"max_404_paths_per_ip"`
	MaxUserAgentsPerIP int   `yaml:"max_user_agents_per_ip"`
	MaxQueriesPerIP    int   `yaml:"max_query_patterns_per_ip"`
	MaxValueBytes      int   `yaml:"max_value_bytes"`
	DegradeAtBytes     int64 `yaml:"degrade_at_bytes"`
	RecoverBelowBytes  int64 `yaml:"recover_below_bytes"`
}

type HealthConfig struct {
	Interval Duration `yaml:"interval"`
}

type PHPFPMConfig struct {
	Enabled  bool               `yaml:"enabled"`
	Interval Duration           `yaml:"interval"`
	Pools    []PHPFPMPoolConfig `yaml:"pools"`
}

type PHPFPMPoolConfig struct {
	Name      string `yaml:"name"`
	StatusURL string `yaml:"status_url"`
}

type DatabaseConfig struct {
	Path string `yaml:"path"`
}

type MaxMindConfig struct {
	Enabled              bool                `yaml:"enabled"`
	Edition              string              `yaml:"edition"`
	AccountID            string              `yaml:"account_id"`
	LicenseKeyEnv        string              `yaml:"license_key_env"`
	LicenseKeyCredential string              `yaml:"license_key_credential"`
	DatabaseDir          string              `yaml:"database_dir"`
	Update               MaxMindUpdateConfig `yaml:"update"`
}

type MaxMindUpdateConfig struct {
	Enabled  bool     `yaml:"enabled"`
	Interval Duration `yaml:"interval"`
}

type OutputConfig struct {
	Log       FileOutputConfig  `yaml:"log"`
	Incidents FileOutputConfig  `yaml:"incidents"`
	Slack     SlackOutputConfig `yaml:"slack"`
}

type FileOutputConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

type SlackOutputConfig struct {
	Enabled           bool     `yaml:"enabled"`
	WebhookEnv        string   `yaml:"webhook_env"`
	WebhookCredential string   `yaml:"webhook_credential"`
	MinimumScore      int      `yaml:"minimum_score"`
	Cooldown          Duration `yaml:"cooldown"`
}

// Load rejects unknown fields and extra YAML documents so typos cannot silently
// change monitoring behavior.
func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config: %w", err)
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return Config{}, errors.New("config must contain one YAML document")
		}
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate also fills documented defaults. It does not require optional
// integrations to be reachable during configuration checks.
func (c *Config) Validate() error {
	if err := c.Detection.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(c.Server.Name) == "" {
		return errors.New("server.name is required")
	}
	if c.Mode == "" {
		c.Mode = "monitor"
	}
	if c.Mode != "monitor" {
		return errors.New("mode must be monitor in V1")
	}
	if len(c.AccessFiles) == 0 {
		return errors.New("at least one access_files entry is required")
	}
	if c.ClientIP.Header == "" {
		c.ClientIP.Header = "x-forwarded-for"
	}
	switch c.ClientIP.Header {
	case "x-forwarded-for", "cf-connecting-ip", "x-real-ip":
	default:
		return errors.New("client_ip.header must be x-forwarded-for, cf-connecting-ip, or x-real-ip")
	}
	for i, value := range c.ClientIP.TrustedProxies {
		if err := validateIPRange(value); err != nil {
			return fmt.Errorf("client_ip.trusted_proxies[%d]: %w", i, err)
		}
	}
	for i, value := range c.Allowlist {
		if err := validateIPRange(value); err != nil {
			return fmt.Errorf("allowlist[%d]: %w", i, err)
		}
	}
	paths := make(map[string]bool)
	for i := range c.AccessFiles {
		a := &c.AccessFiles[i]
		if err := absolutePath(fmt.Sprintf("access_files[%d].path", i), a.Path); err != nil {
			return err
		}
		if paths[a.Path] {
			return fmt.Errorf("duplicate access file path %q", a.Path)
		}
		paths[a.Path] = true
		if a.Site == "" {
			a.Site = siteFromPath(a.Path)
		}
		if strings.TrimSpace(a.Site) == "" {
			return fmt.Errorf("access_files[%d].site is required", i)
		}
		if a.Type != "" && a.Type != "nginx" && a.Type != "apache" {
			return fmt.Errorf("access_files[%d].type must be nginx or apache", i)
		}
	}
	if c.Trigger.Mode == "" {
		c.Trigger.Mode = "always"
	}
	switch c.Trigger.Mode {
	case "always":
	case "cpu":
		if c.Trigger.CPUStart <= 0 || c.Trigger.CPUStart > 100 || c.Trigger.CPUStop < 0 || c.Trigger.CPUStop >= c.Trigger.CPUStart {
			return errors.New("trigger CPU thresholds must satisfy 0 <= cpu_stop < cpu_start <= 100")
		}
		if c.Trigger.StartDuration.Duration <= 0 || c.Trigger.StopDuration.Duration <= 0 {
			return errors.New("trigger start_duration and stop_duration must be positive")
		}
	default:
		return errors.New("trigger.mode must be always or cpu")
	}
	if c.Analysis.Window.Duration == 0 {
		c.Analysis.Window.Duration = 30 * time.Second
	}
	if c.Analysis.Window.Duration < time.Second {
		return errors.New("analysis.window must be at least 1s")
	}
	if c.Analysis.Window.Duration > 60*time.Second || c.Analysis.Window.Duration%time.Second != 0 {
		return errors.New("analysis.window must be a whole number of seconds, at most 60s")
	}
	for _, setting := range []struct {
		name         string
		value        *int
		defaultValue int
	}{
		{"max_active_records", &c.Aggregation.MaxActiveRecords, 2048},
		{"max_paths_per_ip", &c.Aggregation.MaxPathsPerIP, 64},
		{"max_404_paths_per_ip", &c.Aggregation.Max404PathsPerIP, 64},
		{"max_user_agents_per_ip", &c.Aggregation.MaxUserAgentsPerIP, 8},
		{"max_query_patterns_per_ip", &c.Aggregation.MaxQueriesPerIP, 16},
		{"max_value_bytes", &c.Aggregation.MaxValueBytes, 256},
	} {
		if *setting.value == 0 {
			*setting.value = setting.defaultValue
		}
		if *setting.value < 0 {
			return fmt.Errorf("aggregation.%s must be positive", setting.name)
		}
	}
	if c.Aggregation.DegradeAtBytes == 0 {
		c.Aggregation.DegradeAtBytes = 256 << 20
	}
	if c.Aggregation.RecoverBelowBytes == 0 {
		c.Aggregation.RecoverBelowBytes = 192 << 20
	}
	if c.Aggregation.DegradeAtBytes < 1<<20 || c.Aggregation.RecoverBelowBytes < 1<<20 || c.Aggregation.RecoverBelowBytes >= c.Aggregation.DegradeAtBytes {
		return errors.New("aggregation memory thresholds require 1 MiB <= recover_below_bytes < degrade_at_bytes")
	}
	if c.Health.Interval.Duration == 0 {
		c.Health.Interval.Duration = time.Second
	}
	if c.Health.Interval.Duration < time.Second || c.Health.Interval.Duration > time.Minute {
		return errors.New("health.interval must be between 1s and 1m")
	}
	if c.PHPFPM.Enabled {
		if len(c.PHPFPM.Pools) == 0 || len(c.PHPFPM.Pools) > 16 {
			return errors.New("php_fpm.pools must contain 1 to 16 pools when enabled")
		}
		if c.PHPFPM.Interval.Duration == 0 {
			c.PHPFPM.Interval.Duration = 5 * time.Second
		}
		if c.PHPFPM.Interval.Duration < time.Second || c.PHPFPM.Interval.Duration > time.Minute {
			return errors.New("php_fpm.interval must be between 1s and 1m")
		}
		seenPools := make(map[string]bool)
		for i, pool := range c.PHPFPM.Pools {
			if strings.TrimSpace(pool.Name) == "" || seenPools[pool.Name] {
				return fmt.Errorf("php_fpm.pools[%d].name must be nonempty and unique", i)
			}
			seenPools[pool.Name] = true
			parsed, err := url.Parse(pool.StatusURL)
			if err != nil || parsed == nil || parsed.User != nil || parsed.Fragment != "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
				return fmt.Errorf("php_fpm.pools[%d].status_url must be a local HTTP(S) URL without credentials or fragment", i)
			}
			host := parsed.Hostname()
			addr, err := netip.ParseAddr(host)
			if host != "localhost" && (err != nil || !addr.IsLoopback()) {
				return fmt.Errorf("php_fpm.pools[%d].status_url must use a loopback host", i)
			}
		}
	}
	if err := absolutePath("database.path", c.Database.Path); err != nil {
		return err
	}
	if c.MaxMind.Enabled {
		if err := absolutePath("maxmind.database_dir", c.MaxMind.DatabaseDir); err != nil {
			return err
		}
	}
	if c.MaxMind.Update.Enabled {
		if !c.MaxMind.Enabled {
			return errors.New("maxmind.update requires maxmind.enabled")
		}
		if c.MaxMind.AccountID == "" {
			return errors.New("maxmind.account_id is required for updates")
		}
		if c.MaxMind.Edition == "" {
			c.MaxMind.Edition = "GeoIP2-Enterprise"
		}
		switch c.MaxMind.Edition {
		case "GeoIP2-Enterprise", "GeoIP2-ISP", "GeoLite2-ASN", "GeoIP2-City", "GeoLite2-City", "GeoIP2-Country", "GeoLite2-Country":
		default:
			return errors.New("maxmind.edition is not a supported MMDB edition")
		}
		if err := validateSecretRef("maxmind license key", c.MaxMind.LicenseKeyEnv, c.MaxMind.LicenseKeyCredential); err != nil {
			return err
		}
		if c.MaxMind.Update.Interval.Duration == 0 {
			c.MaxMind.Update.Interval.Duration = 24 * time.Hour
		}
		if c.MaxMind.Update.Interval.Duration < time.Hour {
			return errors.New("maxmind.update.interval must be at least 1h")
		}
	}
	if c.Output.Log.Enabled {
		if err := absolutePath("output.log.path", c.Output.Log.Path); err != nil {
			return err
		}
	}
	if c.Output.Incidents.Enabled {
		if err := absolutePath("output.incidents.path", c.Output.Incidents.Path); err != nil {
			return err
		}
	}
	if c.Output.Slack.Enabled {
		if err := validateSecretRef("Slack webhook", c.Output.Slack.WebhookEnv, c.Output.Slack.WebhookCredential); err != nil {
			return err
		}
		if c.Output.Slack.MinimumScore == 0 {
			c.Output.Slack.MinimumScore = 80
		}
		if c.Output.Slack.MinimumScore < 0 || c.Output.Slack.MinimumScore > 100 {
			return errors.New("output.slack.minimum_score must be between 0 and 100")
		}
		if c.Output.Slack.Cooldown.Duration == 0 {
			c.Output.Slack.Cooldown.Duration = 10 * time.Minute
		}
		if c.Output.Slack.Cooldown.Duration < 0 {
			return errors.New("output.slack.cooldown must be positive")
		}
	}
	return nil
}

func absolutePath(name, path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%s must be a clean absolute path", name)
	}
	return nil
}

func siteFromPath(path string) string {
	name := filepath.Base(path)
	name = strings.TrimSuffix(name, ".access.log")
	name = strings.TrimSuffix(name, ".log")
	return name
}

func validateSecretRef(name, env, credential string) error {
	if (env == "") == (credential == "") {
		return fmt.Errorf("%s requires exactly one environment or systemd credential reference", name)
	}
	if env != "" && !environmentName.MatchString(env) {
		return fmt.Errorf("%s environment variable name is invalid", name)
	}
	if credential != "" && (!credentialName.MatchString(credential) || credential == "." || credential == "..") {
		return fmt.Errorf("%s credential name is invalid", name)
	}
	return nil
}

func validateIPRange(value string) error {
	if value == "" {
		return errors.New("IP or CIDR is empty")
	}
	if prefix, err := netip.ParsePrefix(value); err == nil {
		if prefix.Bits() == 0 {
			return errors.New("trust-all/allow-all CIDR is not permitted")
		}
		if prefix.Addr().Is4In6() && prefix.Bits() < 96 {
			return errors.New("mapped IPv4 prefix is too broad")
		}
		return nil
	}
	if _, err := netip.ParseAddr(value); err != nil {
		return errors.New("expected an IP address or CIDR")
	}
	return nil
}
