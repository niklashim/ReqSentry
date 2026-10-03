package replay

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/niklashim/ReqSentry/internal/clientidentity"
	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
	"github.com/niklashim/ReqSentry/internal/parser"
)

type Preview struct {
	Source    string         `json:"source"`
	Site      string         `json:"site"`
	Format    string         `json:"format"`
	Kind      string         `json:"kind"`
	Parsed    int            `json:"parsed"`
	Malformed int            `json:"malformed"`
	Filtered  int            `json:"filtered"`
	Missing   map[string]int `json:"missing"`
	Errors    map[string]int `json:"errors"`
	Samples   []any          `json:"samples"`
}

func SourceConfig(path string, cfg config.Config) config.AccessFile {
	for _, s := range append(append([]config.AccessFile(nil), cfg.AccessFiles...), cfg.ErrorFiles...) {
		if s.Path == path {
			return s
		}
	}
	return config.AccessFile{Path: path, Site: filepath.Base(path), Format: "combined", Kind: "access"}
}
func PreviewSource(ctx context.Context, path string, cfg config.Config, limit int) (Preview, error) {
	p := Preview{Missing: map[string]int{}, Errors: map[string]int{}, Samples: []any{}}
	if limit < 1 || limit > 1000 {
		return p, errors.New("preview limit must be 1 to 1000")
	}
	source := SourceConfig(path, cfg)
	p.Source = source.Path
	p.Site = source.Site
	p.Format = source.Format
	p.Kind = source.Kind
	parse, err := parser.NewSource(source, cfg.LogProfiles)
	if err != nil {
		return p, err
	}
	resolver, err := clientidentity.New(cfg)
	if err != nil {
		return p, err
	}
	file, err := os.Open(path)
	if err != nil {
		return p, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 65536), 1<<20)
	for j := 0; j < limit && scanner.Scan(); j++ {
		if err := ctx.Err(); err != nil {
			return p, err
		}
		if source.Kind == "error" {
			e, err := parse.ParseError(scanner.Text())
			if err != nil {
				p.Malformed++
				p.Errors[err.Error()]++
				continue
			}
			if source.MinimumSeverity != "" && parser.SeverityRank(e.Severity) < parser.SeverityRank(source.MinimumSeverity) {
				p.Filtered++
				continue
			}
			p.Parsed++
			if len(p.Samples) < 5 {
				p.Samples = append(p.Samples, e)
			}
			continue
		}
		e, err := parse.Parse(scanner.Text())
		if err != nil {
			p.Malformed++
			p.Errors[err.Error()]++
			continue
		}
		resolved, excluded := resolver.Resolve(e)
		p.Parsed++
		for _, f := range []struct {
			name   string
			absent bool
		}{{"request_time", e.RequestTime == nil}, {"upstream_time", e.UpstreamTime == nil}, {"user_agent", e.UserAgent == nil}, {"bytes", e.Bytes == nil}, {"request_id", e.RequestID == ""}} {
			if f.absent {
				p.Missing[f.name]++
			}
		}
		if len(p.Samples) < 5 {
			p.Samples = append(p.Samples, map[string]any{"timestamp": e.Timestamp, "site": e.SiteID, "logged_ip": e.LogIP, "peer_ip": e.PeerIP, "resolved_client_ip": resolved.ClientIP, "identity_changed": resolved.ClientIP != e.PeerIP, "allowlisted": excluded, "method": e.Method, "status": e.Status, "request_time": e.RequestTime, "upstream_time": e.UpstreamTime, "path": "<redacted>", "query": "<redacted>"})
		}
	}
	return p, scanner.Err()
}

type SourceSummary struct {
	MissingFields map[string]uint64 `json:"missing_fields"`
	Parsed        uint64            `json:"parsed"`
	BadLines      uint64            `json:"malformed"`
	Errors        uint64            `json:"errors"`
	Filtered      uint64            `json:"filtered"`
	MissingTiming uint64            `json:"missing_timing"`
}

// Replay ignores ingestion wall time for deterministic historical error evidence.
func replayErrorTime(e model.ErrorEvent) model.ErrorEvent { e.IngestedAt = e.Timestamp.UTC(); return e }
