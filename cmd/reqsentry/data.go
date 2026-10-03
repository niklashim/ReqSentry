package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/daemon"
	"github.com/niklashim/ReqSentry/internal/storage"
)

// The engine and operators hold shared locks; cleaning takes an exclusive lock.
// Keep the lock file in place: unlinking it would let another process lock a new inode.
func dataGuard(path string, exclusive bool) (*os.File, error) {
	resolved, err := canonicalPath(path)
	if err != nil {
		return nil, err
	}
	path = resolved
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	mode := syscall.LOCK_SH
	if exclusive {
		mode = syscall.LOCK_EX
	}
	if err = syscall.Flock(int(f.Fd()), mode|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("ReqSentry data is in use; stop the monitoring engine and retry: %w", err)
	}
	return f, nil
}

var managedOutputSuffix = regexp.MustCompile(`^(?:-?[0-9]+\.-?[0-9]+\.-?[0-9]+\.archive|-?[0-9]+\.-?[0-9]+\.quarantine)$`)

func canonicalPath(path string) (string, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	// Resolve every existing ancestor even when the leaf does not exist.
	suffix := []string{}
	for {
		resolved, err := filepath.EvalSymlinks(path)
		if err == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return resolved, nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(path)
		if parent == path {
			return "", err
		}
		suffix = append(suffix, filepath.Base(path))
		path = parent
	}
}

func dataFiles(cfg config.Config, configPath string) ([]string, error) {
	candidates := []string{cfg.Database.Path, cfg.Database.Path + "-wal", cfg.Database.Path + "-shm", cfg.Database.Path + "-journal"}
	for _, path := range []string{cfg.Output.Log.Path, cfg.Output.Incidents.Path} {
		if path == "" {
			continue
		}
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, fmt.Errorf("output path must be clean and absolute: %s", path)
		}
		candidates = append(candidates, path)
		entries, err := os.ReadDir(filepath.Dir(path))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		prefix := filepath.Base(path) + ".reqsentry."
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), prefix) && managedOutputSuffix.MatchString(strings.TrimPrefix(e.Name(), prefix)) {
				candidates = append(candidates, filepath.Join(filepath.Dir(path), e.Name()))
			}
		}
	}
	protected := []string{configPath, cfg.Database.Path + ".lock"}
	for _, source := range append(append([]config.AccessFile(nil), cfg.AccessFiles...), cfg.ErrorFiles...) {
		protected = append(protected, source.Path)
	}
	canonicalProtected := []string{}
	for _, path := range protected {
		p, err := canonicalPath(path)
		if err != nil {
			return nil, err
		}
		canonicalProtected = append(canonicalProtected, p)
	}
	mmdbDir := ""
	if cfg.MaxMind.DatabaseDir != "" {
		var err error
		mmdbDir, err = canonicalPath(cfg.MaxMind.DatabaseDir)
		if err != nil {
			return nil, err
		}
	}
	var files []string
	seen := map[string]bool{}
	for _, path := range candidates {
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("refusing to remove non-regular data file: %s", path)
		}
		resolved, err := canonicalPath(path)
		if err != nil {
			return nil, err
		}
		if mmdbDir != "" && (resolved == mmdbDir || strings.HasPrefix(resolved, mmdbDir+string(os.PathSeparator))) {
			return nil, fmt.Errorf("data target overlaps MaxMind files: %s", path)
		}
		for i, p := range canonicalProtected {
			match, _ := filepath.Match(p, resolved)
			protectedInfo, statErr := os.Stat(protected[i])
			if resolved == p || match || (statErr == nil && os.SameFile(info, protectedInfo)) {
				return nil, fmt.Errorf("data target overlaps configuration or input logs: %s", path)
			}
		}
		if path == cfg.Database.Path {
			f, err := os.Open(path)
			if err != nil {
				return nil, err
			}
			header := make([]byte, 16)
			_, err = io.ReadFull(f, header)
			f.Close()
			if err != nil || !bytes.Equal(header, []byte("SQLite format 3\x00")) {
				return nil, fmt.Errorf("refusing to remove an unrecognized SQLite file: %s", path)
			}
		}
		if !seen[resolved] {
			seen[resolved] = true
			files = append(files, path)
		}
	}
	sort.Strings(files)
	return files, nil
}

func cleanData(cfg config.Config, configPath string, preview, confirm bool, stdout, stderr io.Writer) int {
	if !preview && !confirm {
		fmt.Fprintln(stderr, "data clean deletes history, error/minute data, offsets, scheduler state, and configured ReqSentry output files. Stop the engine, inspect data preview, then run with -confirm before the command.")
		return 2
	}
	if _, err := dataFiles(cfg, configPath); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	var guard *os.File
	if !preview {
		var err error
		guard, err = dataGuard(cfg.Database.Path, true)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		defer guard.Close()
		dbPath, err := canonicalPath(cfg.Database.Path)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		locked := map[string]bool{dbPath: true}
		for _, path := range []string{cfg.Output.Log.Path, cfg.Output.Incidents.Path} {
			if path == "" {
				continue
			}
			if !filepath.IsAbs(path) || filepath.Clean(path) != path {
				fmt.Fprintln(stderr, "output path must be clean and absolute")
				return 1
			}
			resolved, err := canonicalPath(path)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			if locked[resolved] {
				continue
			}
			locked[resolved] = true
			outputGuard, err := dataGuard(path, true)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			defer outputGuard.Close()
		}
	}
	files, err := dataFiles(cfg, configPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	// Older daemon binaries do not hold the file lock. Refuse their fresh heartbeat too.
	if !preview {
		if _, err := os.Stat(cfg.Database.Path); err == nil {
			store, err := storage.Open(cfg.Database.Path, stderr)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			v, found, readErr := store.GetState(ctx, "daemon.status")
			cancel()
			closeErr := store.Close()
			if readErr != nil || closeErr != nil {
				fmt.Fprintln(stderr, "cannot verify engine stopped:", readErr, closeErr)
				return 1
			}
			var s daemon.Status
			if found {
				if err := json.Unmarshal([]byte(v), &s); err != nil {
					fmt.Fprintln(stderr, "cannot verify engine stopped: invalid heartbeat")
					return 1
				}
				if s.Running && time.Since(s.UpdatedAt) < 30*time.Second {
					fmt.Fprintln(stderr, "engine heartbeat is still running; stop the service and retry after 30 seconds")
					return 1
				}
			}
			// Closing SQLite may remove WAL/SHM; refresh the preflight list.
			files, err = dataFiles(cfg, configPath)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
		}
	}
	for _, path := range files {
		if preview {
			fmt.Fprintln(stdout, "Would remove:", terminalText(path, 512))
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			fmt.Fprintln(stderr, "cleanup stopped:", err)
			return 1
		}
		fmt.Fprintln(stdout, "Removed:", terminalText(path, 512))
	}
	if preview {
		fmt.Fprintf(stdout, "%d file(s). Configuration, input logs, MaxMind databases, and external messages are preserved.\n", len(files))
	} else {
		fmt.Fprintln(stdout, "ReqSentry data cleaned. Restart the engine to create fresh state; existing input logs start at EOF.")
	}
	return 0
}
