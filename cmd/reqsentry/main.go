package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/daemon"
	"github.com/niklashim/ReqSentry/internal/enrichment"
	"github.com/niklashim/ReqSentry/internal/output"
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
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "unexpected arguments; use -config PATH and optional -check")
		return 2
	}
	cfg, err := config.Load(*path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if *check {
		fmt.Fprintln(stdout, "configuration valid (monitor mode)")
		return 0
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
	if cfg.MaxMind.Enabled {
		manager, err := enrichment.New(cfg.MaxMind.DatabaseDir)
		if err != nil {
			logger.Printf("MaxMind local data unavailable; detection continues without enrichment: %v", err)
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
	if len(sinks) > 0 {
		service.SetIncidentSink(sinks)
	}
	if err := service.Run(ctx); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
