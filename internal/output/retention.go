package output

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type fileRetention struct {
	age  time.Duration
	kind string
}

func (r *fileRetention) recordTime(data []byte) (time.Time, error) {
	if r.kind == "incidents" {
		var v struct {
			Timestamp time.Time `json:"timestamp"`
		}
		if err := json.Unmarshal(bytes.TrimSpace(data), &v); err != nil {
			return time.Time{}, err
		}
		if v.Timestamp.IsZero() {
			return time.Time{}, errors.New("missing timestamp")
		}
		return v.Timestamp, nil
	}
	if len(data) < 19 {
		return time.Time{}, errors.New("missing logger timestamp")
	}
	return time.ParseInLocation("2006/01/02 15:04:05", string(data[:19]), time.Local)
}

func archiveName(path string, lo, hi time.Time) string {
	return fmt.Sprintf("%s.reqsentry.%d.%d.%d.archive", path, lo.UnixNano(), hi.UnixNano(), time.Now().UnixNano())
}
func (r *fileRetention) rotate(path string, lo, hi time.Time) error {
	if lo.IsZero() {
		return nil
	}
	return os.Rename(path, archiveName(path, lo, hi))
}

// Archives carry their earliest/latest record times. Most cleanup only needs
// metadata; only an archive straddling the cutoff needs a streaming rewrite.
func (r *fileRetention) pruneArchives(path string, now time.Time) error {
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		return err
	}
	prefix := filepath.Base(path) + ".reqsentry."
	cutoff := now.Add(-r.age)
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		parts := strings.Split(strings.TrimPrefix(entry.Name(), prefix), ".")
		if len(parts) != 4 || parts[3] != "archive" {
			continue
		}
		lo, e1 := strconv.ParseInt(parts[0], 10, 64)
		hi, e2 := strconv.ParseInt(parts[1], 10, 64)
		_, e3 := strconv.ParseInt(parts[2], 10, 64)
		if e1 != nil || e2 != nil || e3 != nil || hi < lo {
			continue
		}
		name := filepath.Join(filepath.Dir(path), entry.Name())
		if time.Unix(0, hi).Before(cutoff) {
			if err := os.Remove(name); err != nil {
				return err
			}
			continue
		}
		if time.Unix(0, lo).Before(cutoff) {
			first, last, err := r.pruneFile(name, now)
			if err != nil {
				return err
			}
			if first.IsZero() {
				if err := os.Remove(name); err != nil {
					return err
				}
			} else {
				if err := os.Rename(name, archiveName(path, first, last)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Compact a legacy output or the single boundary archive. Multiline logger
// continuations inherit their preceding record's date. Malformed JSONL aborts
// cleanup rather than silently deleting evidence. Atomic rename publishes only
// a complete result, and existing filesystem permissions are preserved.
func (r *fileRetention) pruneFile(path string, now time.Time) (time.Time, time.Time, error) {
	var first, last time.Time
	input, err := os.Open(path)
	if os.IsNotExist(err) {
		return first, last, nil
	}
	if err != nil {
		return first, last, err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil {
		return first, last, err
	}
	if !info.Mode().IsRegular() {
		return first, last, errors.New("output is not a regular file")
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".reqsentry-retention-*")
	if err != nil {
		return first, last, err
	}
	defer func() { tmp.Close(); os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		return first, last, err
	}
	reader := bufio.NewReader(input)
	writer := bufio.NewWriter(tmp)
	cutoff := now.Add(-r.age)
	var previous time.Time
	removed := false
	for {
		line, readErr := readRetentionLine(reader)
		if len(line) > 0 {
			at, err := r.recordTime(line)
			if err != nil {
				if r.kind == "operational" && !previous.IsZero() {
					at = previous
				} else {
					return first, last, errors.New("undated output record prevents retention")
				}
			}
			previous = at
			if at.Before(cutoff) {
				removed = true
			} else {
				if first.IsZero() || at.Before(first) {
					first = at
				}
				if last.IsZero() || at.After(last) {
					last = at
				}
				if _, err := writer.Write(line); err != nil {
					return first, last, err
				}
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return first, last, readErr
		}
	}
	if err := writer.Flush(); err != nil {
		return first, last, err
	}
	if !removed {
		return first, last, nil
	}
	if err := tmp.Sync(); err != nil {
		return first, last, err
	}
	if err := tmp.Close(); err != nil {
		return first, last, err
	}
	current, err := os.Stat(path)
	if err != nil || !os.SameFile(info, current) || info.Size() != current.Size() || !info.ModTime().Equal(current.ModTime()) {
		return first, last, errors.New("output rotated during retention")
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return first, last, err
	}
	return first, last, nil
}

func readRetentionLine(reader *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		part, err := reader.ReadSlice('\n')
		if len(line)+len(part) > 1<<20 {
			return nil, errors.New("output line exceeds retention limit")
		}
		line = append(line, part...)
		if err != bufio.ErrBufferFull {
			return line, err
		}
	}
}
