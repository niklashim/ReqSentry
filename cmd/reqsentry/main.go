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
	limit := flags.Int("limit", 20, "incident report limit (1–1000)")
	jsonOutput := flags.Bool("json", false, "machine-readable status, report, and replay output")
	ip := flags.String("ip", "", "filter report by client IP")
	site := flags.String("site", "", "filter report by configured site")
	details := flags.Bool("details", false, "include signal weights and saved requests in reports")
	confirm := flags.Bool("confirm", false, "confirm deletion for data clean")
	flags.Usage = func() { printUsage(stderr, flags) }
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	command := strings.Join(flags.Args(), " ")
	isReplay := flags.NArg() > 0 && flags.Arg(0) == "replay"
	preview := flags.NArg() == 2 && flags.Arg(0) == "preview"
	testNotification := (flags.NArg() == 2 || flags.NArg() == 3) && flags.Arg(0) == "notifications" && flags.Arg(1) == "test"
	if !isReplay && !preview && !testNotification && command != "prune preview" && command != "data clean" && command != "data preview" && command != "ui enable" && command != "ui disable" && command != "notifications preview" && command != "" && command != "config test" && command != "status" && command != "report" && command != "maxmind status" && command != "maxmind update" {
		flags.Usage()
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
	if preview {
		path, err := filepath.Abs(flags.Arg(1))
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		result, err := replay.PreviewSource(context.Background(), path, cfg, *limit)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if err := json.NewEncoder(stdout).Encode(result); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	if command == "ui enable" || command == "ui disable" {
		return toggleUI(*path, command == "ui enable", stdout, stderr)
	}
	if command == "data clean" || command == "data preview" {
		return cleanData(cfg, *path, command == "data preview", *confirm, stdout, stderr)
	}
	if command == "notifications preview" {
		fmt.Fprintln(stdout, "MOCK SLACK INCIDENT — synthetic data; no message sent")
		fmt.Fprintln(stdout, output.SlackIncidentText(mockIncident()))
		return 0
	}
	if testNotification {
		destinations := notificationDestinations(cfg.Output)
		name := flags.Arg(2)
		if name == "" {
			for _, d := range destinations {
				if d.Enabled {
					if name != "" {
						fmt.Fprintln(stderr, "multiple destinations enabled; specify a name (legacy output.slack is legacy-slack)")
						return 2
					}
					name = d.Name
				}
			}
			if name == "" {
				fmt.Fprintln(stderr, "no notification destinations enabled")
				return 1
			}
		}
		n := output.NewNotifications(destinations, log.New(stderr, "", 0), cfg.Server.Name)
		defer n.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := n.Test(ctx, name); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintln(stdout, "synthetic notification accepted; verify receipt at the destination")
		return 0
	}
	if command == "prune preview" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		p, err := storage.PreviewPruneFile(ctx, cfg.Database.Path, cfg.Database.Retention, time.Now())
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if err := json.NewEncoder(stdout).Encode(p); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
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
		var table *incidentPrinter
		if !*jsonOutput {
			table = newIncidentPrinter(stdout, "Historical log analysis — MONITOR ONLY", *details)
		}
		summary, err := replay.Run(context.Background(), paths, cfg, func(incident model.Incident) error {
			if *jsonOutput {
				return encoder.Encode(incident)
			}
			return table.Write(incident)
		})
		if table != nil {
			if flushErr := table.Close(); err == nil {
				err = flushErr
			}
		}
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if !*jsonOutput {
			_, err := fmt.Fprintf(stdout, "\nParsed: %d  Malformed: %d  Allowlisted: %d  Dropped: %d  Errors: %d  Incidents: %d\n", summary.Parsed, summary.BadLines, summary.Allowlisted, summary.Dropped, summary.ErrorEvents, summary.Incidents)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			return 0
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
		return runOperator(command, operatorOptions{limit: *limit, json: *jsonOutput, ip: *ip, site: *site, details: *details}, cfg, stdout, stderr)
	}
	guard, err := dataGuard(cfg.Database.Path, false)
	guardErr := err
	if guardErr != nil {
		if errors.Is(guardErr, syscall.EWOULDBLOCK) {
			fmt.Fprintln(stderr, guardErr)
			return 1
		}
		fmt.Fprintf(stderr, "SQLite protection lock unavailable; monitoring continues without SQLite: %v\n", guardErr)
	} else {
		defer guard.Close()
	}
	// File output has its own protection so SQLite failure cannot disable it.
	for _, file := range []*config.FileOutputConfig{&cfg.Output.Log, &cfg.Output.Incidents} {
		if !file.Enabled {
			continue
		}
		fileGuard, lockErr := dataGuard(file.Path, false)
		if lockErr != nil {
			if errors.Is(lockErr, syscall.EWOULDBLOCK) {
				fmt.Fprintln(stderr, lockErr)
				return 1
			}
			fmt.Fprintf(stderr, "local output unavailable path=%s; monitoring continues: %v\n", file.Path, lockErr)
			file.Enabled = false
		} else {
			defer fileGuard.Close()
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var logWriter io.Writer = stderr
	if cfg.Output.Log.Enabled {
		file := output.NewRetainedFile(cfg.Output.Log.Path, stderr, cfg.Database.Retention.MaxAge.Duration, "operational")
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
	var store *storage.Store
	err = guardErr
	if guardErr == nil {
		store, err = storage.Open(cfg.Database.Path, stderr)
	}
	if err != nil {
		logger.Printf("SQLite unavailable; monitoring continues without persistent history or restart offsets: %v", err)
	} else {
		defer store.Close()
		store.SetRetention(cfg.Database.Retention)
		maintenanceCtx, maintenanceCancel := context.WithCancel(ctx)
		maintenanceDone := make(chan struct{})
		go func() { defer close(maintenanceDone); store.Maintain(maintenanceCtx, cfg.Database.Retention) }()
		defer func() { maintenanceCancel(); <-maintenanceDone }()
		service.SetCheckpointStore(store)
		sinks = append(sinks, store)
	}
	if cfg.Output.Incidents.Enabled {
		file := output.NewRetainedFile(cfg.Output.Incidents.Path, stderr, cfg.Database.Retention.MaxAge.Duration, "incidents")
		defer file.Close()
		sinks = append(sinks, output.IncidentFile{File: file})
	}
	destinations := notificationDestinations(cfg.Output)
	slackStatus := "disabled"
	if cfg.Output.Slack.Enabled {
		slackStatus = "configured"
	}
	notifications := output.NewNotifications(destinations, logger, cfg.Server.Name)
	defer notifications.Close()
	sinks = append(sinks, notifications)
	service.SetOperationalSink(notifications)
	service.SetNotificationStatus(notifications.Status)
	if store != nil {
		store.SetOperationalSink(notifications)
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
		updater.SetOperationalSink(notifications)
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

func runOperator(command string, options operatorOptions, cfg config.Config, stdout, stderr io.Writer) int {
	if err := options.validate(command); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	guard, err := dataGuard(cfg.Database.Path, false)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer guard.Close()
	if _, err := os.Stat(cfg.Database.Path); err != nil && !strings.HasPrefix(command, "maxmind ") {
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
		if options.json {
			err = encoder.Encode(status)
		} else {
			err = printStatus(stdout, status, cfg.Server.Name)
		}
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	case "report":
		store.SetRetention(cfg.Database.Retention)
		incidents, err := store.FilteredIncidents(ctx, options.limit, options.ip, options.site)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if incidents == nil {
			incidents = []model.Incident{}
		}
		if options.json {
			err = encoder.Encode(incidents)
		} else {
			err = printIncidents(stdout, incidents, options.details)
		}
		if err != nil {
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
