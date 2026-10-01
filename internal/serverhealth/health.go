// Package serverhealth samples Linux /proc outside the request hot path.
package serverhealth

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Snapshot struct {
	Timestamp         time.Time
	CPUPercent        *float64
	Load1             *float64
	Load5             *float64
	Load15            *float64
	MemoryUsedPercent *float64
}

type cpuCounters struct {
	total uint64
	idle  uint64
}

type ProcSampler struct {
	dir      string
	mu       sync.Mutex
	previous *cpuCounters
}

func NewProcSampler(dir string) *ProcSampler {
	return &ProcSampler{dir: dir}
}

// Sample returns all available measurements and joins errors for missing
// inputs. The first CPU sample has no percentage until a second sample exists.
func (s *ProcSampler) Sample(at time.Time) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := Snapshot{Timestamp: at}
	var problems []error
	if data, err := os.ReadFile(filepath.Join(s.dir, "stat")); err != nil {
		problems = append(problems, fmt.Errorf("read proc stat: %w", err))
	} else if current, err := parseCPU(data); err != nil {
		problems = append(problems, err)
	} else {
		if s.previous != nil && current.total > s.previous.total && current.idle >= s.previous.idle {
			deltaTotal := current.total - s.previous.total
			deltaIdle := current.idle - s.previous.idle
			if deltaIdle <= deltaTotal {
				value := 100 * float64(deltaTotal-deltaIdle) / float64(deltaTotal)
				result.CPUPercent = &value
			}
		}
		s.previous = &current
	}
	if data, err := os.ReadFile(filepath.Join(s.dir, "loadavg")); err != nil {
		problems = append(problems, fmt.Errorf("read proc loadavg: %w", err))
	} else if values, err := parseLoad(data); err != nil {
		problems = append(problems, err)
	} else {
		result.Load1, result.Load5, result.Load15 = &values[0], &values[1], &values[2]
	}
	if data, err := os.ReadFile(filepath.Join(s.dir, "meminfo")); err != nil {
		problems = append(problems, fmt.Errorf("read proc meminfo: %w", err))
	} else if used, err := parseMemory(data); err != nil {
		problems = append(problems, err)
	} else {
		result.MemoryUsedPercent = &used
	}
	return result, errors.Join(problems...)
}

func parseCPU(data []byte) (cpuCounters, error) {
	first, _, _ := strings.Cut(string(data), "\n")
	fields := strings.Fields(first)
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuCounters{}, errors.New("invalid /proc/stat CPU line")
	}
	var result cpuCounters
	for i := 1; i < len(fields) && i <= 8; i++ {
		value, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil {
			return cpuCounters{}, errors.New("invalid /proc/stat CPU counter")
		}
		result.total += value
		if i == 4 || i == 5 {
			result.idle += value
		}
	}
	return result, nil
}

func parseLoad(data []byte) ([3]float64, error) {
	fields := strings.Fields(string(data))
	var values [3]float64
	if len(fields) < 3 {
		return values, errors.New("invalid /proc/loadavg")
	}
	for i := range values {
		value, err := strconv.ParseFloat(fields[i], 64)
		if err != nil || value < 0 {
			return values, errors.New("invalid /proc/loadavg value")
		}
		values[i] = value
	}
	return values, nil
}

func parseMemory(data []byte) (float64, error) {
	var total, available uint64
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] != "MemTotal:" && fields[0] != "MemAvailable:" {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, errors.New("invalid /proc/meminfo value")
		}
		if fields[0] == "MemTotal:" {
			total = value
		} else {
			available = value
		}
	}
	if total == 0 || available > total {
		return 0, errors.New("MemTotal or MemAvailable unavailable")
	}
	return 100 * float64(total-available) / float64(total), nil
}
