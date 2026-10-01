package maxmindupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/enrichment"
	"github.com/niklashim/ReqSentry/internal/storage"
)

func archive(t *testing.T, database []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := tarWriter.WriteHeader(&tar.Header{Name: "GeoIP2-Enterprise_20261001/GeoIP2-Enterprise.mmdb", Mode: 0600, Size: int64(len(database))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write(database); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func testUpdater(t *testing.T, existing bool, payload []byte, calls *atomic.Int64) (*Updater, *storage.Store, string) {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "GeoIP2-Enterprise.mmdb")
	if existing {
		fixture, err := os.ReadFile("../enrichment/testdata/GeoIP2-Enterprise.mmdb")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, fixture, 0600); err != nil {
			t.Fatal(err)
		}
	}
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		user, pass, ok := r.BasicAuth()
		if !ok || user != "1234" || pass != "test-license" {
			t.Errorf("missing Basic Auth: %q %q %t", user, pass, ok)
		}
		body := []byte(nil)
		if r.Method == http.MethodGet {
			body = payload
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Last-Modified": []string{"Thu, 01 Oct 2026 10:00:00 GMT"}}, Body: io.NopCloser(bytes.NewReader(body))}, nil
	})
	t.Setenv("REQSENTRY_TEST_MAXMIND_LICENSE", "test-license")
	store, err := storage.Open(filepath.Join(directory, "state.db"), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	reader, _ := enrichment.New(directory)
	t.Cleanup(func() { _ = reader.Close() })
	cfg := config.MaxMindConfig{Enabled: true, Edition: "GeoIP2-Enterprise", AccountID: "1234", LicenseKeyEnv: "REQSENTRY_TEST_MAXMIND_LICENSE", DatabaseDir: directory, Update: config.MaxMindUpdateConfig{Enabled: true, Interval: config.Duration{Duration: 24 * time.Hour}}}
	u := New(cfg, store, reader, log.New(io.Discard, "", 0))
	u.client.Transport = transport
	return u, store, path
}

func TestMissingDatabaseDownloadAndPersistentSchedule(t *testing.T) {
	fixture, err := os.ReadFile("../enrichment/testdata/GeoIP2-Enterprise.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	u, _, path := testUpdater(t, false, archive(t, fixture), &calls)
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	result, err := u.Check(context.Background(), now)
	if err != nil || result.Action != "downloaded" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, fixture) {
		t.Fatalf("installed database invalid: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("requests=%d", calls.Load())
	}
	reopened, err := storage.Open(filepath.Join(filepath.Dir(path), "state.db"), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	result, err = New(u.config, reopened, u.reader, u.logger).Check(context.Background(), now.Add(time.Hour))
	if err != nil || result.Action != "not_due" || calls.Load() != 1 {
		t.Fatalf("restart result=%+v err=%v calls=%d", result, err, calls.Load())
	}
}

func TestExistingDatabaseWaitsAndFailedDownloadPreservesIt(t *testing.T) {
	var calls atomic.Int64
	u, _, path := testUpdater(t, true, archive(t, []byte("invalid mmdb")), &calls)
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	result, err := u.Check(context.Background(), now)
	if err != nil || result.Action != "using_existing" || calls.Load() != 0 {
		t.Fatalf("startup result=%+v err=%v calls=%d", result, err, calls.Load())
	}
	result, err = u.Check(context.Background(), now.Add(24*time.Hour))
	if err == nil || result.State.FailureCount != 1 || calls.Load() != 2 {
		t.Fatalf("failure result=%+v err=%v calls=%d", result, err, calls.Load())
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("working database replaced: %v", err)
	}
	result, err = u.Check(context.Background(), now.Add(24*time.Hour+30*time.Minute))
	if err != nil || result.Action != "not_due" || calls.Load() != 2 {
		t.Fatalf("backoff result=%+v err=%v calls=%d", result, err, calls.Load())
	}
}
