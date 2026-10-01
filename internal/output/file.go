// Package output writes local monitor-mode records without making file I/O
// part of the request ingestion path.
package output

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/niklashim/ReqSentry/internal/model"
)

var ErrQueueFull = errors.New("output queue full")
var ErrClosed = errors.New("output closed")

// File has a bounded queue and reopens its path after log rotation. A failed
// destination drops its own records and reports errors to diagnostics.
type File struct {
	path        string
	diagnostics io.Writer
	queue       chan []byte
	done        chan struct{}
	mu          sync.Mutex
	closed      bool
	dropped     uint64
}

func NewFile(path string, diagnostics io.Writer) *File {
	f := &File{path: path, diagnostics: diagnostics, queue: make(chan []byte, 256), done: make(chan struct{})}
	go f.run()
	return f
}

// Enqueue copies data and returns immediately, including when the destination
// is slow. The caller can surface ErrQueueFull to its operational logger.
func (f *File) Enqueue(data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return ErrClosed
	}
	copyOfData := append([]byte(nil), data...)
	select {
	case f.queue <- copyOfData:
		return nil
	default:
		f.dropped++
		if powerOfTwo(f.dropped) {
			fmt.Fprintf(f.diagnostics, "ReqSentry output queue full path=%s dropped=%d\n", f.path, f.dropped)
		}
		return ErrQueueFull
	}
}

// Write lets a standard logger mirror operational records. It reports queue
// failures through diagnostics while keeping the primary stderr log usable.
func (f *File) Write(data []byte) (int, error) {
	_ = f.Enqueue(data)
	return len(data), nil
}

func (f *File) Close() {
	f.mu.Lock()
	if !f.closed {
		f.closed = true
		close(f.queue)
	}
	f.mu.Unlock()
	<-f.done
}

func (f *File) run() {
	defer close(f.done)
	var active *os.File
	defer func() {
		if active != nil {
			_ = active.Close()
		}
	}()
	var failures uint64
	for record := range f.queue {
		if active != nil {
			current, pathErr := os.Stat(f.path)
			opened, fileErr := active.Stat()
			if pathErr != nil || fileErr != nil || !os.SameFile(current, opened) {
				_ = active.Close()
				active = nil
			}
		}
		if active == nil {
			var err error
			active, err = os.OpenFile(f.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				failures++
				if powerOfTwo(failures) {
					fmt.Fprintf(f.diagnostics, "ReqSentry output unavailable path=%s failures=%d: %v\n", f.path, failures, err)
				}
				continue
			}
		}
		if _, err := active.Write(record); err != nil {
			failures++
			if powerOfTwo(failures) {
				fmt.Fprintf(f.diagnostics, "ReqSentry output write failed path=%s failures=%d: %v\n", f.path, failures, err)
			}
			_ = active.Close()
			active = nil
			continue
		}
		if failures > 0 {
			fmt.Fprintf(f.diagnostics, "ReqSentry output recovered path=%s at=%s\n", f.path, time.Now().Format(time.RFC3339))
			failures = 0
		}
	}
}

func powerOfTwo(value uint64) bool { return value > 0 && value&(value-1) == 0 }

type IncidentFile struct{ File *File }

func (s IncidentFile) WriteIncident(_ context.Context, incident model.Incident) error {
	encoded, err := json.Marshal(incident)
	if err != nil {
		return err
	}
	return s.File.Enqueue(append(encoded, '\n'))
}
