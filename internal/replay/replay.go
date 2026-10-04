// Package replay evaluates historical access logs without starting the daemon
// or any network integration.
package replay

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/niklashim/ReqSentry/internal/aggregator"
	"github.com/niklashim/ReqSentry/internal/clientidentity"
	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/correlation"
	"github.com/niklashim/ReqSentry/internal/detector"
	"github.com/niklashim/ReqSentry/internal/enrichment"
	"github.com/niklashim/ReqSentry/internal/model"
	"github.com/niklashim/ReqSentry/internal/parser"
	"github.com/niklashim/ReqSentry/internal/scoring"
	"github.com/niklashim/ReqSentry/internal/serverhealth"
)

type Summary struct {
	Sources       map[string]*SourceSummary `json:"sources,omitempty"`
	ErrorEvents   uint64                    `json:"error_events"`
	Parsed        uint64                    `json:"parsed"`
	BadLines      uint64                    `json:"bad_lines"`
	Allowlisted   uint64                    `json:"allowlisted"`
	Dropped       uint64                    `json:"dropped"`
	Incidents     uint64                    `json:"incidents"`
	MaxMind       string                    `json:"maxmind"`
	ASNExclusions model.ASNExclusionStatus  `json:"asn_exclusions"`
}

type source struct {
	file      *os.File
	scanner   *bufio.Scanner
	site      string
	parser    *parser.Source
	nextError *model.ErrorEvent
	stats     *SourceSummary
	last      time.Time
	next      model.RequestEvent
	ready     bool
}

func (s *source) advance(summary *Summary) error {
	s.ready = false
	s.nextError = nil
	for s.scanner.Scan() {
		var event model.RequestEvent
		var err error
		if s.parser.File.Kind == "error" {
			var e model.ErrorEvent
			e, err = s.parser.ParseError(s.scanner.Text())
			if err == nil {
				if minimum := s.parser.File.MinimumSeverity; minimum != "" && parser.SeverityRank(e.Severity) < parser.SeverityRank(minimum) {
					s.stats.Filtered++
					continue
				}
				event.Timestamp = e.Timestamp
				e = replayErrorTime(e)
				s.nextError = &e
				s.stats.Errors++
			}
		} else {
			event, err = s.parser.Parse(s.scanner.Text())
		}
		if err != nil {
			summary.BadLines++
			s.stats.BadLines++
			continue
		}
		if !s.last.IsZero() && event.Timestamp.Before(s.last) {
			return fmt.Errorf("out-of-order timestamp in source %s", s.site)
		}
		s.last = event.Timestamp
		s.next = event
		s.ready = true
		return nil
	}
	return s.scanner.Err()
}

// Run merges configured log files by timestamp, then evaluates each closed
// analysis window with the same rule engine used by the live daemon.
type Section struct {
	Offset        int64
	Length        int64
	Device, Inode uint64
}

func Run(ctx context.Context, paths []string, cfg config.Config, emit func(model.Incident) error) (Summary, error) {
	return RunSections(ctx, paths, cfg, nil, emit, nil, nil)
}

// RunSections bounds crash recovery to captured file identities and complete-line ranges.
func RunSections(ctx context.Context, paths []string, cfg config.Config, sections map[string]Section, emit func(model.Incident) error, observe func(model.RequestEvent, bool), observeError func(model.ErrorEvent)) (Summary, error) {
	summary := Summary{Sources: map[string]*SourceSummary{}, MaxMind: "disabled"}
	summary.ASNExclusions.Configured = cfg.Detection.ExcludedASNs
	errorsEngine := correlation.New(cfg.Correlation, len(cfg.ErrorFiles) > 0)
	if len(paths) == 0 {
		return summary, fmt.Errorf("replay requires at least one access log")
	}
	resolver, err := clientidentity.New(cfg)
	if err != nil {
		return summary, err
	}
	var geo *enrichment.Manager
	if cfg.MaxMind.Enabled {
		var err error
		geo, err = enrichment.New(cfg.MaxMind.DatabaseDir)
		if geo != nil {
			defer geo.Close()
		}
		summary.MaxMind = "available"
		if err != nil {
			summary.MaxMind = "unavailable"
		}
	}
	scorer, err := scoring.New(cfg.Detection)
	if err != nil {
		return summary, err
	}
	rollup := aggregator.New(cfg.Aggregation, cfg.Analysis.Window.Duration)
	sources := make([]*source, 0, len(paths))
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			for _, prior := range sources {
				_ = prior.file.Close()
			}
			return summary, err
		}
		site := ""
		sourceConfig := SourceConfig(path, cfg)
		for _, configured := range append(append([]config.AccessFile(nil), cfg.AccessFiles...), cfg.ErrorFiles...) {
			if configured.Path == path {
				site = configured.Site
				sourceConfig = configured
				break
			}
		}
		if site == "" && sourceConfig.Kind != "error" {
			site = filepath.Base(path)
			site = strings.TrimSuffix(site, ".access.log")
			site = strings.TrimSuffix(site, ".log")
		}
		var reader io.Reader = file
		if section, ok := sections[path]; ok {
			info, err := file.Stat()
			if err != nil {
				file.Close()
				for _, prior := range sources {
					prior.file.Close()
				}
				return summary, err
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok || uint64(st.Dev) != section.Device || st.Ino != section.Inode || section.Offset < 0 || section.Length < 0 || section.Offset+section.Length > info.Size() {
				file.Close()
				for _, prior := range sources {
					prior.file.Close()
				}
				return summary, fmt.Errorf("recovery source identity/size changed")
			}
			reader = io.NewSectionReader(file, section.Offset, section.Length)
		}
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 64*1024), 1<<20)
		sourceConfig.Site = site
		sourceParser, parseErr := parser.NewSource(sourceConfig, cfg.LogProfiles)
		if parseErr != nil {
			_ = file.Close()
			for _, prior := range sources {
				_ = prior.file.Close()
			}
			return summary, parseErr
		}
		stats := &SourceSummary{MissingFields: map[string]uint64{}}
		summary.Sources[path] = stats
		s := &source{file: file, scanner: scanner, site: site, parser: sourceParser, stats: stats}
		if err := s.advance(&summary); err != nil {
			_ = file.Close()
			for _, prior := range sources {
				_ = prior.file.Close()
			}
			return summary, err
		}
		sources = append(sources, s)
	}
	defer func() {
		for _, source := range sources {
			_ = source.file.Close()
		}
	}()
	window := cfg.Analysis.Window.Duration
	if window <= 0 {
		window = 30 * time.Second
	}
	var end time.Time
	evaluate := func(at time.Time) error {
		all := rollup.TotalRequests(window, at)
		for _, identity := range rollup.ActiveIdentities(window, at) {
			snapshot, ok := rollup.Snapshot(identity.SiteID, identity.ClientIP, window, at)
			if !ok || snapshot.Requests == 0 {
				continue
			}
			signals := detector.HTTPWithRules(snapshot, cfg.Detection)
			if identity.SiteID == "" {
				signals = append(signals, detector.ImpactWithRules(snapshot, all, rollup.SiteCount(identity.ClientIP, window, at), serverhealth.Snapshot{}, nil, cfg.Detection)...)
			}
			if len(signals) == 0 {
				continue
			}
			metadata, geoStatus := enrichment.Result{}, summary.MaxMind
			if geo != nil && geo.Available() {
				var lookupErr error
				metadata, lookupErr = geo.Lookup(snapshot.ClientIP)
				if lookupErr != nil {
					metadata, geoStatus = enrichment.Result{}, "lookup_error"
				} else if !metadata.Found {
					geoStatus = "not_found"
				}
			}
			if len(cfg.Detection.ExcludedASNs) > 0 {
				if metadata.ASN == nil {
					summary.ASNExclusions.UnknownWindows++
				} else if cfg.Detection.ExcludesASN(metadata.ASN) {
					summary.ASNExclusions.ExcludedWindows++
					continue
				}
			}
			incident := scorer.Evaluate(scoring.Input{Server: cfg.Server.Name, Snapshot: snapshot, Signals: signals, AllRequests: all, Enrichment: metadata, EnrichmentStatus: geoStatus})
			incident.Errors = errorsEngine.Context(incident)
			if incident.Decision == model.DecisionNormal {
				continue
			}
			if err := emit(incident); err != nil {
				return err
			}
			summary.Incidents++
		}
		return nil
	}
	for {
		if err := ctx.Err(); err != nil {
			return summary, err
		}
		selected := -1
		for i, source := range sources {
			if source.ready && (selected < 0 || source.next.Timestamp.Before(sources[selected].next.Timestamp)) {
				selected = i
			}
		}
		if selected < 0 {
			break
		}
		event := sources[selected].next
		if end.IsZero() {
			end = event.Timestamp.Truncate(window).Add(window)
		}
		for !event.Timestamp.Before(end) {
			if err := evaluate(end.Add(-time.Nanosecond)); err != nil {
				return summary, err
			}
			end = end.Add(window)
			if event.Timestamp.Sub(end) > time.Minute {
				end = event.Timestamp.Truncate(window).Add(window)
			}
		}
		if sources[selected].nextError != nil {
			errorsEngine.ObserveError(*sources[selected].nextError)
			if observeError != nil {
				observeError(*sources[selected].nextError)
			}
			summary.ErrorEvents++
			if err := sources[selected].advance(&summary); err != nil {
				return summary, err
			}
			continue
		}
		errorsEngine.Prune(event.Timestamp)
		resolved, excluded := resolver.Resolve(event)
		if observe != nil {
			observe(resolved, excluded)
		}
		errorsEngine.Observe(resolved)
		sources[selected].stats.Parsed++
		for _, item := range []struct {
			name    string
			missing bool
		}{{"request_time", resolved.RequestTime == nil}, {"upstream_time", resolved.UpstreamTime == nil}, {"bytes", resolved.Bytes == nil}, {"request_id", resolved.RequestID == ""}} {
			if item.missing {
				sources[selected].stats.MissingFields[item.name]++
			}
		}
		if resolved.RequestTime == nil {
			sources[selected].stats.MissingTiming++
		}
		if excluded {
			summary.Allowlisted++
		}
		if !rollup.Observe(resolved, excluded, event.Timestamp) {
			summary.Dropped++
		}
		summary.Parsed++
		if err := sources[selected].advance(&summary); err != nil {
			return summary, err
		}
	}
	if !end.IsZero() {
		if err := evaluate(end.Add(-time.Nanosecond)); err != nil {
			return summary, err
		}
	}
	return summary, nil
}
