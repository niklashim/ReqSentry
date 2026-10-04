package replay

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
)

func TestReplayLocalASNExclusionAndMissingDatabase(t *testing.T) {
	for _, available := range []bool{true, false} {
		t.Run(fmt.Sprintf("database available %t", available), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "requests.log")
			at := time.Unix(1_800_000_000, 0)
			var lines strings.Builder
			for i := 0; i < 300; i++ {
				for _, ip := range []string{"74.209.24.0", "192.0.2.1"} {
					lines.WriteString(logLine(ip, at, "GET", fmt.Sprintf("/scan/%d", i), 404, ""))
				}
			}
			if err := os.WriteFile(path, []byte(lines.String()), 0600); err != nil {
				t.Fatal(err)
			}
			mmdb := dir
			if available {
				var err error
				mmdb, err = filepath.Abs("../enrichment/testdata")
				if err != nil {
					t.Fatal(err)
				}
			}
			cfg := config.Config{Server: config.ServerConfig{Name: "fixture"}, AccessFiles: []config.AccessFile{{Path: path, Site: "shop"}}, Database: config.DatabaseConfig{Path: filepath.Join(dir, "unused.db")}, MaxMind: config.MaxMindConfig{Enabled: true, DatabaseDir: mmdb}, Detection: config.DefaultDetectionConfig()}
			cfg.Detection.ExcludedASNs = []uint32{14671}
			if err := cfg.Validate(); err != nil {
				t.Fatal(err)
			}
			var known, unknown bool
			summary, err := Run(context.Background(), []string{path}, cfg, func(i model.Incident) error {
				if i.ClientIP.String() == "74.209.24.0" {
					known = true
				} else {
					unknown = true
				}
				return nil
			})
			if err != nil || summary.Parsed != 600 || !unknown {
				t.Fatalf("replay failed: %+v %v", summary, err)
			}
			if available {
				if known || summary.ASNExclusions.ExcludedWindows == 0 || summary.ASNExclusions.UnknownWindows == 0 || summary.MaxMind != "available" {
					t.Fatalf("ASN exclusion failed: %+v", summary)
				}
			} else if !known || summary.ASNExclusions.ExcludedWindows != 0 || summary.MaxMind != "unavailable" {
				t.Fatalf("unavailable data granted an exclusion: %+v", summary)
			}
			if _, err := os.Stat(cfg.Database.Path); !os.IsNotExist(err) {
				t.Fatal("replay initialized live state")
			}
		})
	}
}
