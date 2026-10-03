package main

import (
	"flag"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"
	"unicode"

	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/daemon"
	"github.com/niklashim/ReqSentry/internal/model"
)

type operatorOptions struct {
	limit    int
	json     bool
	ip, site string
	details  bool
}

func (o *operatorOptions) validate(command string) error {
	if command != "report" {
		return nil
	}
	if o.limit < 1 || o.limit > 1000 {
		return fmt.Errorf("limit must be between 1 and 1000")
	}
	if o.ip != "" {
		ip, err := netip.ParseAddr(o.ip)
		if err != nil || ip.Zone() != "" {
			return fmt.Errorf("ip must be an IPv4 or IPv6 address")
		}
		o.ip = ip.Unmap().String()
	}
	return nil
}

func printUsage(w io.Writer, flags *flag.FlagSet) {
	fmt.Fprintln(w, `ReqSentry — log monitoring and IP incident reporting (monitor only)
Usage: reqsentry [flags] [command]
Place flags before the command. No command starts the monitoring engine.

  config test                Validate configuration
  status                     Show engine, source, and delivery health
  report                     List recent IP findings (-ip, -site, -details)
  replay LOG...              Analyze historical logs without saving or sending
  preview LOG                Preview normalized/redacted log records (JSON)
  notifications preview      Show a synthetic Slack incident; sends nothing
  notifications test [NAME]  Send a synthetic test to an enabled destination
  maxmind status             Inspect update schedule (JSON)
  maxmind update             Run the configured update check (JSON; respects due time)
  ui enable | ui disable     Save UI setting; restart service to apply
  data preview               List configured ReqSentry data files to remove
  data clean                 Remove those files; stop engine and use -confirm
  prune preview              Preview retention cleanup (JSON)

Flags:`)
	flags.PrintDefaults()
}

// Keep untrusted site names and saved paths from controlling the terminal.
func terminalText(s string, max int) string {
	var b strings.Builder
	count := 0
	for _, r := range s {
		if count >= max {
			b.WriteRune('…')
			break
		}
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			r = ' '
		}
		b.WriteRune(r)
		count++
	}
	return b.String()
}

type incidentPrinter struct {
	w       io.Writer
	details bool
	count   int
	err     error
}

func newIncidentPrinter(w io.Writer, title string, details bool) *incidentPrinter {
	p := &incidentPrinter{w: w, details: details}
	_, p.err = fmt.Fprintf(w, "%s\nDecisions describe the incident window; no IP is blocked. Times are UTC.\n\n%-20s %-39s %-24s %5s %-12s %8s %7s %s\n", title, "DETECTED", "CLIENT IP", "SITE", "SCORE", "DECISION", "REQUESTS", "PEAK/s", "COUNTRY")
	return p
}
func (p *incidentPrinter) Write(i model.Incident) error {
	if p.err != nil {
		return p.err
	}
	site := i.SiteID
	if site == "" {
		site = "All sites"
	}
	country := i.Country
	if country == "" {
		country = "—"
	}
	_, p.err = fmt.Fprintf(p.w, "%-20s %-39s %-24s %5d %-12s %8d %7d %s\n", i.Timestamp.UTC().Format("2006-01-02 15:04:05"), i.ClientIP, terminalText(site, 24), i.Score, terminalText(string(i.Decision), 12), i.Requests, i.PeakRPS, terminalText(country, 32))
	codes := make([]string, 0, len(i.Signals))
	for _, signal := range i.Signals {
		codes = append(codes, terminalText(signal.Code, 64))
	}
	if p.err == nil {
		_, p.err = fmt.Fprintln(p.w, "  Evidence:", strings.Join(codes, ", "))
	}
	if p.details && p.err == nil {
		_, p.err = fmt.Fprintf(p.w, "  Server: %s  Window: %s – %s  Ruleset: %d\n", terminalText(i.Server, 80), i.WindowStart.UTC().Format(time.RFC3339), i.WindowEnd.UTC().Format(time.RFC3339), i.RulesetVersion)
		for _, s := range i.Signals {
			if p.err != nil {
				break
			}
			_, p.err = fmt.Fprintf(p.w, "    %s: weight=%d strength=%s\n", terminalText(s.Code, 64), s.Weight, terminalText(string(s.Strength), 32))
		}
		for _, r := range i.RequestSamples {
			if p.err != nil {
				break
			}
			_, p.err = fmt.Fprintf(p.w, "    %s %s %s → %d\n", r.Timestamp.UTC().Format(time.RFC3339), terminalText(r.Method, 16), terminalText(r.Path, 160), r.Status)
		}
		if i.EvidenceDegraded && p.err == nil {
			_, p.err = fmt.Fprintln(p.w, "  Coverage: degraded; some evidence is incomplete")
		}
	}
	p.count++
	return p.err
}
func (p *incidentPrinter) Close() error {
	if p.err != nil {
		return p.err
	}
	if p.count == 0 {
		_, p.err = fmt.Fprintln(p.w, "No retained findings matched. This does not certify that traffic is safe.")
	}
	return p.err
}
func printIncidents(w io.Writer, incidents []model.Incident, details bool) error {
	p := newIncidentPrinter(w, "Recent IP findings — MONITOR ONLY", details)
	for _, i := range incidents {
		if err := p.Write(i); err != nil {
			return err
		}
	}
	return p.Close()
}
func printStatus(w io.Writer, s daemon.Status, server string) error {
	state := "stopped / heartbeat unavailable"
	if s.Running {
		state = "running"
	}
	ui := "disabled"
	if s.Web.Enabled {
		ui = s.Web.Status
	}
	heartbeat := "unavailable"
	if !s.UpdatedAt.IsZero() {
		heartbeat = s.UpdatedAt.UTC().Format(time.RFC3339)
	}
	_, err := fmt.Fprintf(w, "ReqSentry | %s | MONITOR ONLY\nEngine: %s  Analysis active: %t\nLast heartbeat: %s\nSQLite: %s  MaxMind: %s  UI: %s\n", terminalText(server, 80), state, s.TriggerActive, heartbeat, terminalText(s.SQLite, 40), terminalText(s.MaxMind, 40), terminalText(ui, 40))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "Aggregation: active=%d dropped=%d old=%d degraded=%t\n", s.Aggregation.ActiveRecords, s.Aggregation.DroppedEvents, s.Aggregation.OldEvents, s.Aggregation.Degraded)
	if err != nil {
		return err
	}
	if !s.Health.Timestamp.IsZero() {
		cpu, memory, load := "unavailable", "unavailable", "unavailable"
		if s.Health.CPUPercent != nil {
			cpu = fmt.Sprintf("%.1f%%", *s.Health.CPUPercent)
		}
		if s.Health.MemoryUsedPercent != nil {
			memory = fmt.Sprintf("%.1f%%", *s.Health.MemoryUsedPercent)
		}
		if s.Health.Load1 != nil {
			load = fmt.Sprintf("%.2f", *s.Health.Load1)
		}
		_, err = fmt.Fprintf(w, "Health sampled %s: CPU=%s memory=%s load1=%s\n", s.Health.Timestamp.UTC().Format(time.RFC3339), cpu, memory, load)
	} else {
		_, err = fmt.Fprintln(w, "Health: unavailable")
	}
	if err != nil {
		return err
	}
	if _, err = fmt.Fprintln(w, "\nLOG SOURCES"); err != nil {
		return err
	}
	for _, source := range s.WatchedLogs {
		if err != nil {
			return err
		}
		state := "unavailable"
		if source.Open {
			state = "open"
		}
		_, err = fmt.Fprintf(w, "  %s [%s] %s | parsed=%d malformed=%d lag=%d bytes\n", terminalText(source.Site, 80), state, terminalText(source.Path, 256), source.Parsed, source.BadLines, source.LagBytes)
		if source.LastError != "" && err == nil {
			_, err = fmt.Fprintln(w, "    Last error:", terminalText(source.LastError, 256))
		}
	}
	if err != nil {
		return err
	}
	if len(s.WatchedLogs) == 0 {
		_, err = fmt.Fprintln(w, "  No source heartbeat recorded yet.")
	}
	if err != nil {
		return err
	}
	if len(s.Notifications) == 0 {
		_, err = fmt.Fprintln(w, "Notifications: no destination heartbeat recorded.")
	}
	for _, d := range s.Notifications {
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(w, "Notification %s (%s): %s | queued=%d accepted=%d failed=%d dropped=%d\n", terminalText(d.Name, 80), terminalText(d.Type, 20), terminalText(d.State, 40), d.Queued, d.Delivered, d.Failed, d.Dropped)
	}
	return err
}

func notificationDestinations(cfg config.OutputConfig) []config.DestinationConfig {
	destinations := append([]config.DestinationConfig(nil), cfg.Destinations...)
	if cfg.Slack.Enabled {
		s := cfg.Slack
		destinations = append(destinations, config.DestinationConfig{Name: "legacy-slack", Type: "slack", Enabled: true, WebhookEnv: s.WebhookEnv, WebhookCredential: s.WebhookCredential, MinimumScore: s.MinimumScore, Cooldown: s.Cooldown, Operational: true, QueueSize: 128, MaxAttempts: 3, MaxAge: config.Duration{Duration: time.Minute}})
	}
	return destinations
}

func mockIncident() model.Incident {
	start := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	return model.Incident{Timestamp: start.Add(30 * time.Second), Server: "web-example-01", SiteID: "shop.example", ClientIP: netip.MustParseAddr("203.0.113.31"), WindowStart: start, WindowEnd: start.Add(30 * time.Second), Requests: 600, PeakRPS: 20, Score: 100, Decision: model.DecisionWouldBlock, MonitorOnly: true, EnrichmentStatus: "disabled", Signals: []model.Signal{{Code: "HIGH_404_RATE"}, {Code: "HIGH_404_DIVERSITY"}, {Code: "PATH_ENUMERATION"}, {Code: "HIGH_REQUEST_RATE"}, {Code: "SUSTAINED_HIGH_RATE"}, {Code: "METHOD_404_SCAN"}, {Code: "AUTOMATED_USER_AGENT"}}}
}
