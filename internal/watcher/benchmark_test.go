package watcher

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
)

func BenchmarkWatcherBatchLag(b *testing.B) {
	var sample strings.Builder
	for i := 0; i < 1000; i++ {
		sample.WriteString(fmt.Sprintf("192.0.2.1 - - [01/Oct/2026:12:00:00 +0000] \"GET /%d HTTP/1.1\" 200 12 \"-\" \"Mozilla\"\n", i))
	}
	var totalLag time.Duration
	for iteration := 0; iteration < b.N; iteration++ {
		b.StopTimer()
		dir := b.TempDir()
		path := filepath.Join(dir, "access.log")
		if err := os.WriteFile(path, nil, 0600); err != nil {
			b.Fatal(err)
		}
		var parsed atomic.Int64
		manager := New([]config.AccessFile{{Path: path, Site: "site"}}, log.New(io.Discard, "", 0), func(model.RequestEvent) { parsed.Add(1) })
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { manager.Run(ctx); close(done) }()
		deadline := time.Now().Add(3 * time.Second)
		for !manager.Status()[0].Open && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if !manager.Status()[0].Open {
			cancel()
			<-done
			b.Fatal("watcher did not open")
		}
		file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			cancel()
			<-done
			b.Fatal(err)
		}
		b.StartTimer()
		start := time.Now()
		if _, err := file.WriteString(sample.String()); err != nil {
			b.Fatal(err)
		}
		_ = file.Close()
		for parsed.Load() < 1000 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		lag := time.Since(start)
		b.StopTimer()
		totalLag += lag
		cancel()
		<-done
		if parsed.Load() != 1000 {
			b.Fatalf("parsed=%d", parsed.Load())
		}
	}
	b.ReportMetric(float64(totalLag.Milliseconds())/float64(b.N), "batch_lag_ms")
}
