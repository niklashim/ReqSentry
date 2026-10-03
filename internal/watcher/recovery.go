package watcher

import (
	"context"
	"errors"
	"github.com/niklashim/ReqSentry/internal/storage"
	"time"
)

type boundary struct {
	at     time.Time
	offset int64
}

func (m *Manager) SetResumeOffsets(offsets map[string]storage.Offset) {
	for _, s := range m.sources {
		if o, ok := offsets[s.config.Path]; ok {
			copy := o
			s.resume = &copy
		}
	}
}
func (s *source) trackBoundary(file *openLog, offset int64) {
	now := time.Now().Truncate(time.Second)
	if len(file.boundaries) == 0 || !file.boundaries[len(file.boundaries)-1].at.Equal(now) {
		if len(file.boundaries) >= 121 {
			copy(file.boundaries, file.boundaries[1:])
			file.boundaries = file.boundaries[:120]
		}
		file.boundaries = append(file.boundaries, boundary{at: now, offset: offset})
	}
}
func (m *Manager) safeOffsets(now time.Time, lookback time.Duration, maxBytes int64) (map[string]storage.Offset, error) {
	out := map[string]storage.Offset{}
	var bytes int64
	for _, s := range m.sources {
		if len(s.retiring) > 0 {
			return nil, errors.New("rotation still draining; checkpoint deferred")
		}
		if s.active == nil {
			continue
		}
		f := s.active
		offset := f.committedOffset
		for _, b := range f.boundaries {
			if !b.at.Before(now.Add(-lookback)) {
				offset = b.offset
				break
			}
		}
		if offset > f.committedOffset {
			return nil, errors.New("truncated source boundary; checkpoint deferred")
		}
		bytes += f.committedOffset - offset
		if bytes > maxBytes {
			return nil, errors.New("recovery overlap exceeds byte budget; checkpoint deferred")
		}
		dev, inode, ok := fileIdentity(f.info)
		if !ok {
			return nil, errors.New("source identity unavailable")
		}
		out[s.config.Path] = storage.Offset{Device: dev, Inode: inode, Bytes: offset}
	}
	return out, nil
}

// PeriodicCheckpoints pauses source readers only around a bounded local flush/transaction.
// Offsets retain raw overlap rather than dropping an unfinished analysis window.
func (m *Manager) PeriodicCheckpoints(ctx context.Context, interval, lookback time.Duration, maxBytes int64) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			m.gate.Lock()
			offsets, err := m.safeOffsets(now, lookback, maxBytes)
			if err == nil {
				writeCtx, cancel := context.WithTimeout(ctx, time.Second)
				err = m.checkpoints.Flush(writeCtx)
				if err == nil {
					err = m.checkpoints.SaveOffsets(writeCtx, offsets)
				}
				cancel()
			}
			for _, s := range m.sources {
				s.mu.Lock()
				if err == nil {
					at := now
					s.status.LastCheckpointAt = &at
					s.status.RecoveryError = ""
				} else {
					s.status.RecoveryError = err.Error()
				}
				s.mu.Unlock()
			}
			m.gate.Unlock()
		}
	}
}

func (m *Manager) ConfigureRecovery(lookback time.Duration, maxBytes int64) {
	m.recovery = true
	m.recoveryLookback = lookback
	m.recoveryMaxBytes = maxBytes
}
