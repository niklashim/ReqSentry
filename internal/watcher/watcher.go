// Package watcher follows configured access logs without making one missing
// file stop the other sites. It starts at EOF for files present on startup.
package watcher

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
	"github.com/niklashim/ReqSentry/internal/parser"
	"github.com/niklashim/ReqSentry/internal/storage"
)

const (
	defaultPollInterval = 250 * time.Millisecond
	rotationGrace       = 2 * time.Second
	maxLineBytes        = 1 << 20
	maxRetiringFiles    = 4
)

type Status struct {
	LagBytes         int64
	ParseErrors      map[string]uint64
	MissingFields    map[string]uint64
	Kind             string
	Format           string
	Filtered         uint64
	LastRecordAt     *time.Time
	LastCheckpointAt *time.Time
	RecoveryError    string
	Path             string
	Site             string
	Open             bool
	Parsed           uint64
	BadLines         uint64
	IOErrors         uint64
	LastError        string
}

type Manager struct {
	gate             sync.RWMutex
	sources          []*source
	logger           *log.Logger
	onEvent          func(model.RequestEvent)
	poll             time.Duration
	checkpoints      *storage.Store
	afterDrain       func() bool
	recovery         bool
	recoveryLookback time.Duration
	recoveryMaxBytes int64
}

type source struct {
	gate           *sync.RWMutex
	resume         *storage.Offset
	onError        func(model.ErrorEvent)
	parser         *parser.Source
	config         config.AccessFile
	mu             sync.RWMutex
	status         Status
	active         *openLog
	retiring       []*openLog
	initialMissing bool
	started        bool
	logger         *log.Logger
	onEvent        func(model.RequestEvent)
	checkpoints    *storage.Store
}

type openLog struct {
	boundaries      []boundary
	file            *os.File
	info            os.FileInfo
	reader          *bufio.Reader
	offset          int64
	committedOffset int64
	pending         []byte
	discard         bool
	retireAfter     time.Time
}

func New(files []config.AccessFile, logger *log.Logger, onEvent func(model.RequestEvent)) *Manager {
	m := &Manager{logger: logger, onEvent: onEvent, poll: defaultPollInterval}
	for _, file := range files {
		m.sources = append(m.sources, &source{
			gate:    &m.gate,
			parser:  sourceParser(file, nil),
			config:  file,
			status:  Status{ParseErrors: map[string]uint64{}, MissingFields: map[string]uint64{}, Path: file.Path, Site: file.Site, Kind: file.Kind, Format: file.Format},
			logger:  logger,
			onEvent: onEvent,
		})
	}
	return m
}

func (m *Manager) SetCheckpointStore(store *storage.Store) {
	m.checkpoints = store
	for _, source := range m.sources {
		source.checkpoints = store
	}
}

// SetAfterDrain runs once every source has stopped before clean checkpoints
// advance. Returning false preserves the prior checkpoint for crash replay.
func (m *Manager) SetAfterDrain(callback func() bool) { m.afterDrain = callback }

func (m *Manager) Run(ctx context.Context) {
	var group sync.WaitGroup
	for _, s := range m.sources {
		group.Add(1)
		go func(s *source) {
			defer group.Done()
			s.run(ctx, m.poll)
		}(s)
	}
	group.Wait()
	if m.afterDrain == nil || m.afterDrain() {
		m.CommitOffsets()
	}
}

func (m *Manager) CommitOffsets() {
	m.gate.Lock()
	defer m.gate.Unlock()
	if m.recovery && m.checkpoints != nil {
		offsets, err := m.safeOffsets(time.Now(), m.recoveryLookback, m.recoveryMaxBytes)
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			err = m.checkpoints.SaveOffsets(ctx, offsets)
			cancel()
		}
		if err != nil {
			m.logger.Print("clean recovery checkpoint deferred; prior safe offsets retained")
		}
		return
	}
	for _, source := range m.sources {
		if source.active != nil {
			source.saveCheckpoint(source.active, source.active.committedOffset)
		}
	}
}

func (m *Manager) Status() []Status {
	result := make([]Status, 0, len(m.sources))
	for _, s := range m.sources {
		s.mu.RLock()
		item := s.status
		item.ParseErrors = map[string]uint64{}
		for k, v := range s.status.ParseErrors {
			item.ParseErrors[k] = v
		}
		item.MissingFields = map[string]uint64{}
		for k, v := range s.status.MissingFields {
			item.MissingFields[k] = v
		}
		result = append(result, item)
		s.mu.RUnlock()
	}
	return result
}

func (s *source) run(ctx context.Context, poll time.Duration) {
	defer s.closeAll()
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	s.step()
	for {
		select {
		case <-ctx.Done():
			// Drain complete lines already written before shutdown.
			s.gate.RLock()
			s.drainAll()
			s.gate.RUnlock()
			return
		case <-ticker.C:
			s.step()
		}
	}
}

func (s *source) step() {
	s.gate.RLock()
	defer s.gate.RUnlock()
	info, err := os.Stat(s.config.Path)
	if err != nil {
		if !s.started {
			s.initialMissing = true
		}
		s.recordIO(err)
	} else if s.active == nil || !os.SameFile(info, s.active.info) {
		// A replacement is read from byte zero. Keep the old descriptor briefly
		// so writes racing with logrotate can still be observed.
		startAtEnd := !s.started && !s.initialMissing
		resumeAt := int64(-1)
		priorOffset := int64(-1)
		if !s.started && s.checkpoints != nil {
			checkpoint, found, loadErr := s.checkpoints.LoadOffset(context.Background(), s.config.Path)
			if loadErr != nil {
				s.logger.Printf("access log checkpoint unavailable path=%s: %v", s.config.Path, loadErr)
			} else if found {
				if at, err := s.checkpoints.OffsetUpdatedAt(context.Background(), s.config.Path); err == nil {
					s.mu.Lock()
					s.status.LastCheckpointAt = &at
					s.mu.Unlock()
				}
				device, inode, ok := fileIdentity(info)
				if ok && checkpoint.Device == device && checkpoint.Inode == inode && checkpoint.Bytes >= 0 && checkpoint.Bytes <= info.Size() {
					resumeAt = checkpoint.Bytes
					priorOffset = checkpoint.Bytes
					startAtEnd = false
				}
			}
		}
		if !s.started && s.resume != nil {
			dev, inode, ok := fileIdentity(info)
			if ok && dev == s.resume.Device && inode == s.resume.Inode && s.resume.Bytes <= info.Size() {
				resumeAt = s.resume.Bytes
				startAtEnd = false
			}
		}
		replacement, err := openFile(s.config.Path, info, startAtEnd, resumeAt)
		if err != nil {
			s.recordIO(err)
		} else {
			if s.active != nil {
				s.active.retireAfter = time.Now().Add(rotationGrace)
				s.retiring = append(s.retiring, s.active)
				s.logger.Printf("access log rotated path=%s site=%s", s.config.Path, s.config.Site)
			}
			if s.resume != nil && priorOffset >= 0 && priorOffset < replacement.committedOffset {
				replacement.boundaries = append(replacement.boundaries, boundary{at: time.Now().Truncate(time.Second), offset: priorOffset})
			}
			s.active = replacement
			s.started = true
			s.setOpen(true)
			s.clearError()
			s.logger.Printf("watching log source path=%s site=%s kind=%s format=%s", s.config.Path, s.config.Site, s.config.Kind, s.config.Format)
			if resumeAt < 0 {
				s.saveCheckpoint(replacement, replacement.offset)
			}
		}
	} else {
		s.clearError()
	}
	s.drainAll()
	s.closeRetiring()
}

func openFile(path string, info os.FileInfo, atEnd bool, resumeAt int64) (*openLog, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	actual, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if !os.SameFile(info, actual) {
		file.Close()
		return nil, errors.New("access log changed while opening")
	}
	var offset int64
	if resumeAt >= 0 {
		offset, err = file.Seek(resumeAt, io.SeekStart)
		if err != nil {
			file.Close()
			return nil, err
		}
	} else if atEnd {
		offset, err = file.Seek(0, io.SeekEnd)
		if err != nil {
			file.Close()
			return nil, err
		}
	}
	return &openLog{file: file, info: actual, reader: bufio.NewReaderSize(file, 64*1024), offset: offset, committedOffset: offset}, nil
}

func (s *source) drainAll() {
	if s.active != nil {
		s.drain(s.active)
	}
	for _, old := range s.retiring {
		s.drain(old)
	}
}

func (s *source) drain(file *openLog) {
	info, err := file.file.Stat()
	if err != nil {
		s.recordIO(err)
		return
	}
	if info.Size() < file.offset {
		if _, err := file.file.Seek(0, io.SeekStart); err != nil {
			s.recordIO(err)
			return
		}
		file.reader.Reset(file.file)
		file.offset = 0
		file.committedOffset = 0
		file.pending = nil
		file.boundaries = nil
		file.discard = false
		s.logger.Printf("access log truncated path=%s site=%s", s.config.Path, s.config.Site)
	}
	readAny := false
	startOffset := file.offset
	completeLines := 0
	for {
		if file.offset-startOffset >= 8<<20 || completeLines >= 16384 {
			break
		}
		fragment, err := file.reader.ReadSlice('\n')
		if len(fragment) > 0 {
			readAny = true
			file.offset += int64(len(fragment))
			if !file.discard {
				if len(file.pending)+len(fragment) > maxLineBytes {
					file.pending = nil
					file.discard = true
				} else {
					file.pending = append(file.pending, fragment...)
				}
			}
		}
		if err == nil {
			s.trackBoundary(file, file.committedOffset)
			if file.discard {
				s.recordBad(errors.New("access-log line exceeds 1 MiB"))
			} else {
				line := bytes.TrimSuffix(file.pending, []byte{'\n'})
				line = bytes.TrimSuffix(line, []byte{'\r'})
				s.handleLine(string(line))
			}
			file.pending = nil
			file.discard = false
			file.committedOffset = file.offset
			completeLines++
			continue
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if !errors.Is(err, io.EOF) {
			s.recordIO(err)
		}
		break
	}
	s.mu.Lock()
	s.status.LagBytes = max(int64(0), info.Size()-file.committedOffset)
	s.mu.Unlock()
	if readAny && !file.retireAfter.IsZero() {
		file.retireAfter = time.Now().Add(rotationGrace)
	}
}

func (s *source) handleLine(line string) {
	if s.config.Kind == "error" {
		if s.parser == nil {
			s.recordBad(errors.New("error parser unavailable"))
			return
		}
		event, err := s.parser.ParseError(line)
		if err != nil {
			s.recordBad(err)
			return
		}
		if s.config.MinimumSeverity != "" && parser.SeverityRank(event.Severity) < parser.SeverityRank(s.config.MinimumSeverity) {
			s.mu.Lock()
			s.status.Filtered++
			s.mu.Unlock()
			return
		}
		s.mu.Lock()
		s.status.Parsed++
		now := time.Now().UTC()
		s.status.LastRecordAt = &now
		s.mu.Unlock()
		if s.onError != nil {
			s.onError(event)
		}
		return
	}

	var event model.RequestEvent
	var err error
	if s.parser == nil {
		err = errors.New("source parser unavailable")
	} else {
		event, err = s.parser.Parse(line)
	}
	if err != nil {
		s.recordBad(err)
		return
	}
	s.mu.Lock()
	s.status.Parsed++
	now := time.Now().UTC()
	s.status.LastRecordAt = &now
	for _, item := range []struct {
		name    string
		missing bool
	}{{"request_time", event.RequestTime == nil}, {"upstream_time", event.UpstreamTime == nil}, {"bytes", event.Bytes == nil}, {"request_id", event.RequestID == ""}} {
		if item.missing {
			s.status.MissingFields[item.name]++
		}
	}
	s.mu.Unlock()
	if s.onEvent != nil {
		s.onEvent(event)
	}
}

func (s *source) recordBad(err error) {
	s.mu.Lock()
	s.status.BadLines++
	category := parseCategory(err)
	s.status.ParseErrors[category]++
	count := s.status.BadLines
	s.mu.Unlock()
	if powerOfTwo(count) {
		s.logger.Printf("skipped malformed access log path=%s site=%s count=%d: %v", s.config.Path, s.config.Site, count, parser.RedactMessage(err.Error()))
	}
}

func (s *source) recordIO(err error) {
	s.mu.Lock()
	s.status.IOErrors++
	count := s.status.IOErrors
	s.status.LastError = err.Error()
	s.mu.Unlock()
	if powerOfTwo(count) {
		s.logger.Printf("access log unavailable path=%s site=%s failures=%d: %v", s.config.Path, s.config.Site, count, parser.RedactMessage(err.Error()))
	}
}

func (s *source) clearError() {
	s.mu.Lock()
	s.status.LastError = ""
	s.mu.Unlock()
}

func (s *source) setOpen(open bool) {
	s.mu.Lock()
	s.status.Open = open
	s.mu.Unlock()
}

func (s *source) closeRetiring() {
	now := time.Now()
	remaining := s.retiring[:0]
	for i, old := range s.retiring {
		if now.After(old.retireAfter) || len(s.retiring)-i > maxRetiringFiles {
			if err := old.file.Close(); err != nil {
				s.recordIO(fmt.Errorf("close rotated log: %w", err))
			}
			continue
		}
		remaining = append(remaining, old)
	}
	s.retiring = remaining
}

func (s *source) closeAll() {
	if s.active != nil {
		s.active.file.Close()
	}
	for _, old := range s.retiring {
		old.file.Close()
	}
	s.setOpen(false)
}

func (s *source) saveCheckpoint(file *openLog, offset int64) {
	if s.checkpoints == nil {
		return
	}
	device, inode, ok := fileIdentity(file.info)
	if !ok {
		s.logger.Printf("access log checkpoint identity unavailable path=%s", s.config.Path)
		return
	}
	if err := s.checkpoints.SaveOffset(context.Background(), s.config.Path, storage.Offset{Device: device, Inode: inode, Bytes: offset}); err != nil {
		s.logger.Printf("access log checkpoint save failed path=%s: %v", s.config.Path, err)
	}
}

func fileIdentity(info os.FileInfo) (uint64, uint64, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return uint64(stat.Dev), uint64(stat.Ino), true
}

func powerOfTwo(value uint64) bool {
	return value != 0 && value&(value-1) == 0
}

func sourceParser(file config.AccessFile, profiles map[string]config.LogProfile) *parser.Source {
	p, _ := parser.NewSource(file, profiles)
	return p
}
func (m *Manager) SetProfiles(profiles map[string]config.LogProfile) {
	for _, s := range m.sources {
		s.parser = sourceParser(s.config, profiles)
	}
}

func (m *Manager) SetErrorSink(sink func(model.ErrorEvent)) {
	for _, s := range m.sources {
		s.onError = sink
	}
}

func parseCategory(err error) string {
	v := err.Error()
	for _, kind := range []string{"timestamp", "client IP", "peer IP", "HTTP status", "duration", "duplicate", "line exceeds", "JSON", "logfmt"} {
		if strings.Contains(v, kind) {
			return kind
		}
	}
	return "invalid_record"
}
