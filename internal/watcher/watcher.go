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
	Path      string
	Site      string
	Open      bool
	Parsed    uint64
	BadLines  uint64
	IOErrors  uint64
	LastError string
}

type Manager struct {
	sources     []*source
	logger      *log.Logger
	onEvent     func(model.RequestEvent)
	poll        time.Duration
	checkpoints *storage.Store
	afterDrain  func() bool
}

type source struct {
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
			config:  file,
			status:  Status{Path: file.Path, Site: file.Site},
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
		result = append(result, s.status)
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
			s.drainAll()
			return
		case <-ticker.C:
			s.step()
		}
	}
}

func (s *source) step() {
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
		if !s.started && s.checkpoints != nil {
			checkpoint, found, loadErr := s.checkpoints.LoadOffset(context.Background(), s.config.Path)
			if loadErr != nil {
				s.logger.Printf("access log checkpoint unavailable path=%s: %v", s.config.Path, loadErr)
			} else if found {
				device, inode, ok := fileIdentity(info)
				if ok && checkpoint.Device == device && checkpoint.Inode == inode && checkpoint.Bytes >= 0 && checkpoint.Bytes <= info.Size() {
					resumeAt = checkpoint.Bytes
					startAtEnd = false
				}
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
			s.active = replacement
			s.started = true
			s.setOpen(true)
			s.clearError()
			s.logger.Printf("watching access log path=%s site=%s", s.config.Path, s.config.Site)
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
		file.discard = false
		s.logger.Printf("access log truncated path=%s site=%s", s.config.Path, s.config.Site)
	}
	readAny := false
	for {
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
	if readAny && !file.retireAfter.IsZero() {
		file.retireAfter = time.Now().Add(rotationGrace)
	}
}

func (s *source) handleLine(line string) {
	event, err := parser.Parse(line, s.config.Site)
	if err != nil {
		s.recordBad(err)
		return
	}
	s.mu.Lock()
	s.status.Parsed++
	s.mu.Unlock()
	if s.onEvent != nil {
		s.onEvent(event)
	}
}

func (s *source) recordBad(err error) {
	s.mu.Lock()
	s.status.BadLines++
	count := s.status.BadLines
	s.mu.Unlock()
	if powerOfTwo(count) {
		s.logger.Printf("skipped malformed access log path=%s site=%s count=%d: %v", s.config.Path, s.config.Site, count, err)
	}
}

func (s *source) recordIO(err error) {
	s.mu.Lock()
	s.status.IOErrors++
	count := s.status.IOErrors
	s.status.LastError = err.Error()
	s.mu.Unlock()
	if powerOfTwo(count) {
		s.logger.Printf("access log unavailable path=%s site=%s failures=%d: %v", s.config.Path, s.config.Site, count, err)
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
