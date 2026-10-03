package output

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func datedJSON(at time.Time, label string) []byte {
	v, _ := json.Marshal(map[string]any{"timestamp": at, "label": label})
	return append(v, '\n')
}

func TestOutputRetentionPreservesRecentRecordsAndPermissions(t *testing.T) {
	for _, kind := range []string{"incidents", "operational"} {
		t.Run(kind, func(t *testing.T) {
			now := time.Now().Truncate(time.Second)
			old := now.Add(-97 * time.Hour)
			recent := now.Add(-95 * time.Hour)
			path := filepath.Join(t.TempDir(), "output.log")
			data := append(datedJSON(old, "expired"), datedJSON(recent, "retained")...)
			if kind == "operational" {
				data = []byte(old.Format("2006/01/02 15:04:05") + " expired\nold continuation\n" + recent.Format("2006/01/02 15:04:05") + " retained\nrecent continuation\n")
			}
			if err := os.WriteFile(path, data, 0640); err != nil {
				t.Fatal(err)
			}
			r := fileRetention{age: 96 * time.Hour, kind: kind}
			first, last, err := r.pruneFile(path, now)
			if err != nil || !first.Equal(recent) || !last.Equal(recent) {
				t.Fatalf("range %v %v %v", first, last, err)
			}
			got, err := os.ReadFile(path)
			if err != nil || bytes.Contains(got, []byte("expired")) || bytes.Contains(got, []byte("old continuation")) || !bytes.Contains(got, []byte("retained")) {
				t.Fatalf("retention content %s %v", got, err)
			}
			info, _ := os.Stat(path)
			if info.Mode().Perm() != 0640 {
				t.Fatal("permissions changed")
			}
			if err := r.rotate(path, first, last); err != nil {
				t.Fatal(err)
			}
			if err := r.pruneArchives(path, now.Add(2*time.Hour)); err != nil {
				t.Fatal(err)
			}
			entries, _ := os.ReadDir(filepath.Dir(path))
			if len(entries) != 0 {
				t.Fatalf("expired archive left: %+v", entries)
			}
		})
	}
}

func TestArchiveBoundaryPrunesOnlyExpiredDataAndOwnedFiles(t *testing.T) {
	now := time.Now()
	path := filepath.Join(t.TempDir(), "incidents.jsonl")
	old := now.Add(-97 * time.Hour)
	recent := now.Add(-95 * time.Hour)
	r := fileRetention{96 * time.Hour, "incidents"}
	name := archiveName(path, old, recent)
	if err := os.WriteFile(name, append(datedJSON(old, "expired"), datedJSON(recent, "retained")...), 0600); err != nil {
		t.Fatal(err)
	}
	unrelated := path + ".unrelated"
	if err := os.WriteFile(unrelated, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := r.pruneArchives(path, now); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	found := 0
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".archive") {
			data, _ := os.ReadFile(filepath.Join(filepath.Dir(path), entry.Name()))
			if bytes.Contains(data, []byte("expired")) || !bytes.Contains(data, []byte("retained")) {
				t.Fatal("boundary archive incorrect")
			}
			found++
		}
	}
	if found != 1 {
		t.Fatal("retained archive missing")
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatal("unrelated file removed")
	}
}

func TestRetainedWriterCleansLegacyOutputEvenWhileIdle(t *testing.T) {
	now := time.Now()
	path := filepath.Join(t.TempDir(), "incidents.jsonl")
	data := append(datedJSON(now.Add(-5*24*time.Hour), "expired"), datedJSON(now.Add(-time.Hour), "retained")...)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	f := NewRetainedFile(path, io.Discard, 96*time.Hour, "incidents")
	f.Close()
	entries, _ := os.ReadDir(filepath.Dir(path))
	var all []byte
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(filepath.Dir(path), entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, data...)
	}
	if bytes.Contains(all, []byte("expired")) || !bytes.Contains(all, []byte("retained")) {
		t.Fatalf("idle startup cleanup: %s", all)
	}
}

func TestRetentionMalformedOrOversizedDataIsVisibleAndAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "incidents.jsonl")
	data := []byte("invalid JSON\n")
	os.WriteFile(path, data, 0600)
	r := fileRetention{96 * time.Hour, "incidents"}
	if _, _, err := r.pruneFile(path, time.Now()); err == nil {
		t.Fatal("silently removed malformed evidence")
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, data) {
		t.Fatal("failed cleanup changed file")
	}
	if _, err := readRetentionLine(bufio.NewReader(strings.NewReader(strings.Repeat("x", 2<<20)))); err == nil {
		t.Fatal("accepted oversized line")
	}
}
