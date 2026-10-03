package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/niklashim/ReqSentry/internal/aggregator"
	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
	"github.com/niklashim/ReqSentry/internal/replay"
	"github.com/niklashim/ReqSentry/internal/storage"
)

type RecoveryStatus struct {
	Enabled  bool   `json:"enabled"`
	State    string `json:"state"`
	Replayed uint64 `json:"replayed"`
	Bytes    int64  `json:"bytes"`
	Detail   string `json:"detail,omitempty"`
}

func (d *Daemon) recover(ctx context.Context, rollup *aggregator.Aggregator) (map[string]storage.Offset, RecoveryStatus, error) {
	status := RecoveryStatus{Enabled: true, State: "ready"}
	resume := map[string]storage.Offset{}
	sections := map[string]replay.Section{}
	paths := []string{}
	now := time.Now()
	window := d.config.Analysis.Window.Duration
	for _, src := range append(append([]config.AccessFile(nil), d.config.AccessFiles...), d.config.ErrorFiles...) {
		checkpoint, found, err := d.checkpointStore.LoadOffset(ctx, src.Path)
		if err != nil {
			return nil, status, err
		}
		if !found {
			continue
		}
		file, err := os.Open(src.Path)
		if err != nil {
			return nil, status, errors.New("recovery source unavailable; prior offsets retained")
		}
		info, err := file.Stat()
		if err != nil {
			file.Close()
			return nil, status, err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || uint64(st.Dev) != checkpoint.Device || st.Ino != checkpoint.Inode || info.Size() < checkpoint.Bytes {
			file.Close()
			return nil, status, errors.New("recovery source replaced/truncated; prior offsets retained")
		}
		// A trailing partial line must remain unread for the live watcher.
		end := info.Size()
		if end > checkpoint.Bytes {
			buffer := make([]byte, min(int64(1<<20), end-checkpoint.Bytes))
			n, err := file.ReadAt(buffer, end-int64(len(buffer)))
			if err != nil && n == 0 {
				file.Close()
				return nil, status, err
			}
			last := -1
			for j := n - 1; j >= 0; j-- {
				if buffer[j] == '\n' {
					last = j
					break
				}
			}
			if last < 0 {
				if end-checkpoint.Bytes <= 1<<20 {
					end = checkpoint.Bytes
				} else {
					file.Close()
					return nil, status, errors.New("recovery trailing record exceeds line budget")
				}
			}
			if last >= 0 {
				end = end - int64(len(buffer)) + int64(last+1)
			}
		}
		file.Close()
		status.Bytes += end - checkpoint.Bytes
		if status.Bytes > d.config.Recovery.MaxBytes {
			return nil, status, errors.New("recovery exceeds byte budget; prior offsets retained for operator replay")
		}
		sections[src.Path] = replay.Section{Offset: checkpoint.Bytes, Length: end - checkpoint.Bytes, Device: checkpoint.Device, Inode: checkpoint.Inode}
		resume[src.Path] = storage.Offset{Device: checkpoint.Device, Inode: checkpoint.Inode, Bytes: end}
		paths = append(paths, src.Path)
	}
	if len(paths) == 0 {
		return resume, status, nil
	}
	// Validate the captured, bounded ranges before emitting recovered decisions
	// or warming live counters. An out-of-order source must not partially emit.
	if _, err := replay.RunSections(ctx, paths, d.config, sections, func(model.Incident) error { return nil }, nil, nil); err != nil {
		return nil, status, fmt.Errorf("recovery validation failed; prior offsets retained: %w", err)
	}
	summary, err := replay.RunSections(ctx, paths, d.config, sections, func(i model.Incident) error {
		// Replay finishes its last window; a still-open live window must wait.
		if i.WindowEnd.After(now.Truncate(window).Add(-time.Nanosecond)) {
			return nil
		}
		i.EnsureEventID()
		if d.incidentSink != nil {
			return d.incidentSink.WriteIncident(ctx, i)
		}
		return nil
	}, func(r model.RequestEvent, excluded bool) {
		if !r.Timestamp.Before(now.Add(-time.Minute)) {
			rollup.Observe(r, excluded, r.Timestamp)
			d.errors.Observe(r)
		}
	}, func(e model.ErrorEvent) {
		if !e.Timestamp.Before(now.Add(-d.config.Correlation.Window.Duration - time.Minute)) {
			d.errors.ObserveError(e)
		}
	})
	if err != nil {
		return nil, status, fmt.Errorf("recovery parse failed; prior offsets retained: %w", err)
	}
	if err := d.checkpointStore.Flush(ctx); err != nil {
		return nil, status, errors.New("recovery output flush failed; prior offsets retained")
	}
	status.Replayed = summary.Parsed
	return resume, status, nil
}
