// Package replay evaluates historical access logs without starting the daemon
// or any network integration.
package replay

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/niklashim/ReqSentry/internal/aggregator"
	"github.com/niklashim/ReqSentry/internal/clientidentity"
	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/detector"
	"github.com/niklashim/ReqSentry/internal/model"
	"github.com/niklashim/ReqSentry/internal/parser"
	"github.com/niklashim/ReqSentry/internal/scoring"
	"github.com/niklashim/ReqSentry/internal/serverhealth"
)

type Summary struct {
	Parsed      uint64 `json:"parsed"`
	BadLines    uint64 `json:"bad_lines"`
	Allowlisted uint64 `json:"allowlisted"`
	Dropped     uint64 `json:"dropped"`
	Incidents   uint64 `json:"incidents"`
}

type source struct {
	file    *os.File
	scanner *bufio.Scanner
	site    string
	next    model.RequestEvent
	ready   bool
}

func (s *source) advance(summary *Summary) error {
	s.ready = false
	for s.scanner.Scan() {
		event, err := parser.Parse(s.scanner.Text(), s.site)
		if err != nil {
			summary.BadLines++
			continue
		}
		s.next = event
		s.ready = true
		return nil
	}
	return s.scanner.Err()
}

// Run merges configured log files by timestamp, then evaluates each closed
// analysis window with the same rule engine used by the live daemon.
func Run(ctx context.Context, paths []string, cfg config.Config, emit func(model.Incident) error) (Summary, error) {
	var summary Summary
	if len(paths) == 0 {
		return summary, fmt.Errorf("replay requires at least one access log")
	}
	resolver, err := clientidentity.New(cfg)
	if err != nil {
		return summary, err
	}
	scorer, err := scoring.New(cfg.Detection)
	if err != nil {
		return summary, err
	}
	rollup := aggregator.New(cfg.Aggregation)
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
		for _, configured := range cfg.AccessFiles {
			if configured.Path == path {
				site = configured.Site
				break
			}
		}
		if site == "" {
			site = filepath.Base(path)
			site = strings.TrimSuffix(site, ".access.log")
			site = strings.TrimSuffix(site, ".log")
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64*1024), 1<<20)
		s := &source{file: file, scanner: scanner, site: site}
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
			incident := scorer.Evaluate(scoring.Input{Server: cfg.Server.Name, Snapshot: snapshot, Signals: signals, AllRequests: all})
			incident.EnrichmentStatus = "disabled"
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
		resolved, excluded := resolver.Resolve(event)
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
