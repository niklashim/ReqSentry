package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/daemon"
	"github.com/niklashim/ReqSentry/internal/dashboard"
	"github.com/niklashim/ReqSentry/internal/enrichment"
	"github.com/niklashim/ReqSentry/internal/maxmindupdate"
	"github.com/niklashim/ReqSentry/internal/model"
	"github.com/niklashim/ReqSentry/internal/output"
	"github.com/niklashim/ReqSentry/internal/replay"
	"github.com/niklashim/ReqSentry/internal/storage"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("reqsentry", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("config", config.DefaultPath, "path to YAML configuration")
	check := flags.Bool("check", false, "validate configuration and exit")
	limit := flags.Int("limit", 20, "incident report limit")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	command := strings.Join(flags.Args(), " ")
	isReplay := flags.NArg() > 0 && flags.Arg(0) == "replay"
	if !isReplay && command != "" && command != "config test" && command != "status" && command != "report" && command != "maxmind status" && command != "maxmind update" {
		fmt.Fprintln(stderr, "usage: reqsentry [-config PATH] [-check] [config test|status|report|maxmind status|maxmind update|replay LOG...]")
		return 2
	}
	cfg, err := config.Load(*path)
	if isReplay && errors.Is(err, os.ErrNotExist) && *path == config.DefaultPath {
		if flags.NArg() < 2 {
			fmt.Fprintln(stderr, "replay requires at least one access log")
			return 2
		}
		cfg = config.Config{Server: config.ServerConfig{Name: "replay"}, Mode: "monitor", Trigger: config.TriggerConfig{Mode: "always"}, Database: config.DatabaseConfig{Path: "/tmp/reqsentry-replay-unused.db"}}
		for _, value := range flags.Args()[1:] {
			absolute, absoluteErr := filepath.Abs(value)
			if absoluteErr != nil {
				fmt.Fprintln(stderr, absoluteErr)
				return 1
			}
			cfg.AccessFiles = append(cfg.AccessFiles, config.AccessFile{Path: absolute})
		}
		err = cfg.Validate()
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if *check || command == "config test" {
		fmt.Fprintln(stdout, "configuration valid (monitor mode)")
		return 0
	}
	if isReplay {
		if flags.NArg() < 2 {
			fmt.Fprintln(stderr, "replay requires at least one access log")
			return 2
		}
		paths := make([]string, 0, flags.NArg()-1)
		for _, value := range flags.Args()[1:] {
			absolute, err := filepath.Abs(value)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			paths = append(paths, absolute)
		}
		encoder := json.NewEncoder(stdout)
		summary, err := replay.Run(context.Background(), paths, cfg, func(incident model.Incident) error { return encoder.Encode(incident) })
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if err := encoder.Encode(struct {
			Summary replay.Summary `json:"summary"`
		}{summary}); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	if command != "" {
		return runOperator(command, *limit, cfg, stdout, stderr)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var logWriter io.Writer = stderr
	if cfg.Output.Log.Enabled {
		file := output.NewFile(cfg.Output.Log.Path, stderr)
		defer file.Close()
		logWriter = io.MultiWriter(stderr, file)
	}
	logger := log.New(logWriter, "", log.LstdFlags)
	service := daemon.New(cfg, logger)
	var manager *enrichment.Manager
	maxMindStatus := "disabled"
	if cfg.MaxMind.Enabled {
		maxMindStatus = "unavailable"
		manager, err = enrichment.New(cfg.MaxMind.DatabaseDir)
		if err != nil {
			logger.Printf("MaxMind local data unavailable; detection continues without enrichment: %v", err)
		} else {
			maxMindStatus = "available"
		}
		defer manager.Close()
		service.SetEnricher(manager)
	}
	var sinks output.Fanout
	store, err := storage.Open(cfg.Database.Path, stderr)
	if err != nil {
		logger.Printf("SQLite unavailable; monitoring continues without persistent history or restart offsets: %v", err)
	} else {
		defer store.Close()
		service.SetCheckpointStore(store)
		sinks = append(sinks, store)
	}
	if cfg.Output.Incidents.Enabled {
		file := output.NewFile(cfg.Output.Incidents.Path, stderr)
		defer file.Close()
		sinks = append(sinks, output.IncidentFile{File: file})
	}
	var slack *output.Slack
	slackStatus := "disabled"
	if cfg.Output.Slack.Enabled {
		slackStatus = "unavailable"
		slack, err = output.NewSlack(cfg.Output.Slack, logger)
		if err != nil {
			logger.Printf("Slack unavailable; local monitoring continues: %v", err)
		} else {
			slackStatus = "configured"
			defer slack.Close()
			sinks = append(sinks, slack)
			service.SetOperationalSink(slack)
			if store != nil {
				store.SetOperationalSink(slack)
			}
		}
	}
	service.SetIntegrationStatus(maxMindStatus, slackStatus)
	if len(sinks) > 0 {
		service.SetIncidentSink(sinks)
	}
	var webDone chan struct{}
	if cfg.Web.Enabled {
		web, webErr := dashboard.New(cfg.Web, service, store, logger)
		if webErr != nil {
			logger.Printf("dashboard unavailable; local monitoring continues: %v", webErr)
			service.SetWebStatus(daemon.WebStatus{Enabled: true, Status: "config_error"})
		} else {
			web.OnState = func(state dashboard.State) {
				service.SetWebStatus(daemon.WebStatus{Enabled: state.Enabled, Listen: state.Listen, Clients: state.Clients, Status: state.Status})
			}
			webDone = make(chan struct{})
			go func() {
				defer close(webDone)
				if err := web.Run(ctx); err != nil {
					logger.Printf("dashboard unavailable; local monitoring continues: %v", err)
				}
			}()
		}
	}
	var updateDone chan struct{}
	if cfg.MaxMind.Enabled && cfg.MaxMind.Update.Enabled && store != nil && manager != nil {
		updateDone = make(chan struct{})
		updater := maxmindupdate.New(cfg.MaxMind, store, manager, logger)
		if slack != nil {
			updater.SetOperationalSink(slack)
		}
		go func() {
			defer close(updateDone)
			updater.Run(ctx)
		}()
	}
	if err := service.Run(ctx); err != nil {
		stop()
		if updateDone != nil {
			<-updateDone
		}
		if webDone != nil {
			<-webDone
		}
		fmt.Fprintln(stderr, err)
		return 1
	}
	stop()
	if updateDone != nil {
		<-updateDone
	}
	if webDone != nil {
		<-webDone
	}
	return 0
}

func runOperator(command string, limit int, cfg config.Config, stdout, stderr io.Writer) int {
	if _, err := os.Stat(cfg.Database.Path); err != nil {
		fmt.Fprintf(stderr, "SQLite state unavailable: %v\n", err)
		return 1
	}
	store, err := storage.Open(cfg.Database.Path, stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	switch command {
	case "status":
		value, found, err := store.GetState(ctx, "daemon.status")
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		var status daemon.Status
		if found {
			if err := json.Unmarshal([]byte(value), &status); err != nil {
				fmt.Fprintln(stderr, "invalid daemon status:", err)
				return 1
			}
			if time.Since(status.UpdatedAt) > 30*time.Second {
				status.Running = false
			}
		}
		if !found {
			status = daemon.Status{SQLite: "available", MaxMind: "unknown", Slack: "unknown"}
		}
		if err := encoder.Encode(status); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	case "report":
		incidents, err := store.RecentIncidents(ctx, limit)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if incidents == nil {
			incidents = []model.Incident{}
		}
		if err := encoder.Encode(incidents); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	case "maxmind status", "maxmind update":
		if !cfg.MaxMind.Enabled || !cfg.MaxMind.Update.Enabled {
			fmt.Fprintln(stderr, "MaxMind updates are disabled")
			return 1
		}
		reader, readerErr := enrichment.New(cfg.MaxMind.DatabaseDir)
		if reader == nil {
			fmt.Fprintln(stderr, readerErr)
			return 1
		}
		defer reader.Close()
		updater := maxmindupdate.New(cfg.MaxMind, store, reader, log.New(stderr, "", log.LstdFlags))
		if command == "maxmind update" {
			result, err := updater.Check(ctx, time.Now())
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			if err := encoder.Encode(result); err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
		} else {
			state, err := updater.Status(ctx)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			result := struct {
				Edition           string              `json:"edition"`
				Path              string              `json:"path"`
				DatabaseAvailable bool                `json:"database_available"`
				DatabaseError     string              `json:"database_error,omitempty"`
				State             maxmindupdate.State `json:"state"`
			}{
				Edition: cfg.MaxMind.Edition, Path: filepath.Join(cfg.MaxMind.DatabaseDir, cfg.MaxMind.Edition+".mmdb"), DatabaseAvailable: readerErr == nil, State: state,
			}
			if readerErr != nil {
				result.DatabaseError = readerErr.Error()
			}
			if err := encoder.Encode(result); err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
		}
	}
	return 0
}
