package config

import (
	"strings"
	"testing"
	"time"
)

func TestExtensionsValidateWithoutCredentialsOrNetwork(t *testing.T) {
	text := minimalConfig + `log_profiles:
  app:
    duration_unit: ms
    fields:
      timestamp: /meta/time
error_files:
  - path: /var/log/nginx/site1.error.log
    site: site1
    type: nginx
output:
  destinations:
    - name: teams
      type: teams
      enabled: true
      webhook_env: REQSENTRY_MISSING_TEST_TEAMS
    - name: sns
      type: sns
      enabled: true
      topic_arn: arn:aws:sns:eu-west-1:123456789012:alerts
      region: eu-west-1
`
	c, err := loadText(t, text)
	if err != nil {
		t.Fatal(err)
	}
	if c.ErrorFiles[0].Format != "nginx-error" || c.Output.Destinations[0].QueueSize != 128 {
		t.Fatalf("missing defaults %+v", c)
	}
	for _, bad := range []string{strings.Replace(text, "eu-west-1:123456789012:alerts", "eu-west-1:123456789012:alerts.fifo", 1), strings.Replace(text, "region: eu-west-1", "region: us-east-1", 1), strings.Replace(text, "timestamp: /meta/time", "unknown: /meta/time", 1), strings.Replace(text, "duration_unit: ms", "duration_unit: magic", 1), strings.Replace(text, "name: sns", "name: teams", 1)} {
		if _, err := loadText(t, bad); err == nil {
			t.Fatal("accepted invalid extension")
		}
	}
}

func TestUnifiedRetentionDefaultAndOverrides(t *testing.T) {
	for _, tt := range []struct {
		yaml string
		want time.Duration
	}{{"", 96 * time.Hour}, {"  retention:\n    max_age: 48h\n", 48 * time.Hour}, {"  retention:\n    max_age: 240h\n", 240 * time.Hour}, {"  retention:\n    max_age: 48h\n    incidents: 0s\n    minutes: 720h\n", 48 * time.Hour}} {
		text := strings.Replace(minimalConfig, "database:\n", "database:\n"+tt.yaml, 1)
		c, err := loadText(t, text)
		if err != nil {
			t.Fatal(err)
		}
		r := c.Database.Retention
		if r.MaxAge.Duration != tt.want || r.Incidents.Duration != tt.want || r.Errors.Duration != tt.want || r.Minutes.Duration != tt.want {
			t.Fatalf("retention %+v", r)
		}
	}
	for _, age := range []string{"-1h", "30m"} {
		if _, err := loadText(t, strings.Replace(minimalConfig, "database:\n", "database:\n  retention:\n    max_age: "+age+"\n", 1)); err == nil {
			t.Fatal("accepted invalid maximum age")
		}
	}
}
