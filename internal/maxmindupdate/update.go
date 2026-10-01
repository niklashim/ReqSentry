// Package maxmindupdate schedules authenticated MMDB downloads separately from
// traffic ingestion. It never writes into an active MMDB file.
package maxmindupdate

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/enrichment"
	"github.com/niklashim/ReqSentry/internal/storage"
	"github.com/oschwald/maxminddb-golang/v2"
)

const (
	defaultEndpoint  = "https://download.maxmind.com/geoip/databases"
	maxDatabaseBytes = 1 << 30
)

type State struct {
	LastCheck    time.Time `json:"last_check"`
	LastSuccess  time.Time `json:"last_success"`
	NextCheck    time.Time `json:"next_check"`
	FailureCount int       `json:"failure_count"`
	LastModified time.Time `json:"last_modified"`
	LastError    string    `json:"last_error,omitempty"`
}

type Result struct {
	Action string
	State  State
}

type Updater struct {
	config      config.MaxMindConfig
	store       *storage.Store
	reader      *enrichment.Manager
	logger      *log.Logger
	client      *http.Client
	endpoint    string
	mu          sync.Mutex
	operational interface {
		Operational(string, string, uint64) error
	}
}

func (u *Updater) SetOperationalSink(sink interface {
	Operational(string, string, uint64) error
}) {
	u.operational = sink
}

func New(cfg config.MaxMindConfig, store *storage.Store, reader *enrichment.Manager, logger *log.Logger) *Updater {
	client := &http.Client{Timeout: 10 * time.Minute}
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many MaxMind redirects")
		}
		if request.URL.Scheme != "https" {
			return errors.New("MaxMind redirect must use HTTPS")
		}
		if len(via) > 0 && request.URL.Host != via[0].URL.Host {
			request.Header.Del("Authorization")
		}
		return nil
	}
	return &Updater{config: cfg, store: store, reader: reader, logger: logger, client: client, endpoint: defaultEndpoint}
}

func (u *Updater) stateKey() string { return "maxmind.update." + u.config.Edition }

func (u *Updater) Status(ctx context.Context) (State, error) {
	if u.store == nil {
		return State{}, errors.New("SQLite state unavailable")
	}
	value, found, err := u.store.GetState(ctx, u.stateKey())
	if err != nil || !found {
		return State{}, err
	}
	var state State
	if err := json.Unmarshal([]byte(value), &state); err != nil {
		return State{}, fmt.Errorf("decode MaxMind update state: %w", err)
	}
	return state, nil
}

func (u *Updater) save(ctx context.Context, state State) error {
	value, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return u.store.SetState(ctx, u.stateKey(), string(value))
}

func (u *Updater) targetPath() string {
	return filepath.Join(u.config.DatabaseDir, u.config.Edition+".mmdb")
}

// Check performs only work due under persistent state. An existing database
// with no prior scheduler state gets a full interval before its first HEAD.
func (u *Updater) Check(ctx context.Context, now time.Time) (Result, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.store == nil || u.reader == nil {
		return Result{}, errors.New("MaxMind updates require SQLite and a local reader")
	}
	state, err := u.Status(ctx)
	if err != nil {
		return Result{}, err
	}
	_, statErr := os.Stat(u.targetPath())
	if !state.NextCheck.IsZero() && now.Before(state.NextCheck) && (statErr == nil || state.FailureCount > 0) {
		return Result{Action: "not_due", State: state}, nil
	}
	path := u.targetPath()
	buildTime, exists := validLocal(path)
	if exists && state.NextCheck.IsZero() {
		state.NextCheck = now.Add(u.config.Update.Interval.Duration)
		if err := u.save(ctx, state); err != nil {
			return Result{}, err
		}
		return Result{Action: "using_existing", State: state}, nil
	}
	license, err := config.ResolveSecret(u.config.LicenseKeyEnv, u.config.LicenseKeyCredential)
	if err != nil {
		return u.failure(ctx, now, state, err)
	}
	state.LastCheck = now
	var remote time.Time
	if exists {
		remote, err = u.remoteModified(ctx, license)
		if err != nil {
			return u.failure(ctx, now, state, err)
		}
		known := state.LastModified
		if known.IsZero() {
			known = buildTime
		}
		if !remote.IsZero() && !remote.After(known) {
			state.LastSuccess = now
			state.NextCheck = now.Add(u.config.Update.Interval.Duration)
			state.FailureCount = 0
			state.LastError = ""
			state.LastModified = remote
			if err := u.save(ctx, state); err != nil {
				return Result{}, err
			}
			return Result{Action: "up_to_date", State: state}, nil
		}
	}
	getModified, err := u.download(ctx, license)
	if err != nil {
		return u.failure(ctx, now, state, err)
	}
	if remote.IsZero() {
		remote = getModified
	}
	state.LastModified = remote
	state.LastSuccess = now
	state.NextCheck = now.Add(u.config.Update.Interval.Duration)
	state.FailureCount = 0
	state.LastError = ""
	if err := u.save(ctx, state); err != nil {
		return Result{}, err
	}
	return Result{Action: "downloaded", State: state}, nil
}

func (u *Updater) failure(ctx context.Context, now time.Time, state State, cause error) (Result, error) {
	state.FailureCount++
	backoff := time.Hour << min(state.FailureCount-1, 3)
	if backoff > 6*time.Hour {
		backoff = 6 * time.Hour
	}
	state.NextCheck = now.Add(backoff)
	state.LastError = cause.Error()
	if err := u.save(ctx, state); err != nil {
		return Result{}, errors.Join(cause, err)
	}
	return Result{Action: "failed", State: state}, cause
}

func (u *Updater) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		result, err := u.Check(ctx, time.Now())
		if err != nil {
			if result.State.FailureCount == 1 || powerOfTwo(uint64(result.State.FailureCount)) {
				u.logger.Printf("MaxMind update failed failures=%d next=%s: %v", result.State.FailureCount, result.State.NextCheck.Format(time.RFC3339), err)
			}
			if u.operational != nil {
				_ = u.operational.Operational("maxmind_update", err.Error(), uint64(result.State.FailureCount))
			}
		} else if result.Action == "downloaded" || result.Action == "using_existing" {
			u.logger.Printf("MaxMind update action=%s next=%s", result.Action, result.State.NextCheck.Format(time.RFC3339))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (u *Updater) url() string {
	return strings.TrimRight(u.endpoint, "/") + "/" + u.config.Edition + "/download?suffix=tar.gz"
}

func (u *Updater) request(ctx context.Context, method, license string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, method, u.url(), nil)
	if err != nil {
		return nil, err
	}
	request.SetBasicAuth(u.config.AccountID, license)
	response, err := u.client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		return nil, fmt.Errorf("MaxMind %s returned HTTP %d", method, response.StatusCode)
	}
	return response, nil
}

func (u *Updater) remoteModified(ctx context.Context, license string) (time.Time, error) {
	response, err := u.request(ctx, http.MethodHead, license)
	if err != nil {
		return time.Time{}, err
	}
	defer response.Body.Close()
	if value := response.Header.Get("Last-Modified"); value != "" {
		if parsed, err := http.ParseTime(value); err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, nil
}

func validLocal(path string) (time.Time, bool) {
	reader, err := maxminddb.Open(path)
	if err != nil {
		return time.Time{}, false
	}
	defer reader.Close()
	return reader.Metadata.BuildTime(), reader.Verify() == nil
}

func (u *Updater) download(ctx context.Context, license string) (time.Time, error) {
	response, err := u.request(ctx, http.MethodGet, license)
	if err != nil {
		return time.Time{}, err
	}
	defer response.Body.Close()
	modified, _ := http.ParseTime(response.Header.Get("Last-Modified"))
	archive, err := gzip.NewReader(response.Body)
	if err != nil {
		return time.Time{}, fmt.Errorf("decode MaxMind gzip: %w", err)
	}
	defer archive.Close()
	if err := os.MkdirAll(u.config.DatabaseDir, 0700); err != nil {
		return time.Time{}, err
	}
	temporary, err := os.CreateTemp(u.config.DatabaseDir, "."+u.config.Edition+"-*.mmdb.tmp")
	if err != nil {
		return time.Time{}, err
	}
	defer os.Remove(temporary.Name())
	defer temporary.Close()
	if err := temporary.Chmod(0600); err != nil {
		return time.Time{}, err
	}
	tarReader := tar.NewReader(archive)
	found := false
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return time.Time{}, fmt.Errorf("read MaxMind archive: %w", err)
		}
		if filepath.Base(header.Name) != u.config.Edition+".mmdb" || !header.FileInfo().Mode().IsRegular() {
			continue
		}
		if found || header.Size < 1 || header.Size > maxDatabaseBytes {
			return time.Time{}, errors.New("MaxMind archive has duplicate or invalid MMDB entry")
		}
		if _, err := io.CopyN(temporary, tarReader, header.Size); err != nil {
			return time.Time{}, fmt.Errorf("extract MaxMind MMDB: %w", err)
		}
		found = true
	}
	if !found {
		return time.Time{}, errors.New("MaxMind archive did not contain expected MMDB")
	}
	if err := temporary.Sync(); err != nil {
		return time.Time{}, err
	}
	if err := temporary.Close(); err != nil {
		return time.Time{}, err
	}
	reader, err := maxminddb.Open(temporary.Name())
	if err != nil {
		return time.Time{}, fmt.Errorf("validate downloaded MMDB: %w", err)
	}
	verification := reader.Verify()
	_ = reader.Close()
	if verification != nil {
		return time.Time{}, fmt.Errorf("verify downloaded MMDB: %w", verification)
	}
	if err := os.Rename(temporary.Name(), u.targetPath()); err != nil {
		return time.Time{}, fmt.Errorf("install MaxMind MMDB: %w", err)
	}
	if err := u.reader.Reload(); err != nil {
		return time.Time{}, fmt.Errorf("reload MaxMind MMDB: %w", err)
	}
	return modified.UTC(), nil
}

func powerOfTwo(value uint64) bool { return value != 0 && value&(value-1) == 0 }
