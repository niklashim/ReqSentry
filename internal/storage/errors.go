package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
)

func (s *Store) WriteError(e model.ErrorEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	now := time.Now().Unix()
	if now != s.errorSampleSecond {
		s.errorSampleSecond = now
		s.errorSampleCount = 0
	}
	if s.errorSampleCount >= s.errorSampleLimit {
		return errors.New("SQLite error sample rate exceeded")
	}
	s.errorSampleCount++
	select {
	case s.errorQueue <- e:
		return nil
	default:
		s.writeLoss = ErrQueueFull
		return errors.New("SQLite error queue full")
	}
}
func (s *Store) insertErrors(batch []model.ErrorEvent) error {
	if len(batch) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, e := range batch {
		b, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`INSERT INTO error_events(timestamp_ns,site_id,severity,category,payload_json) VALUES(?,?,?,?,?)`, e.Timestamp.UnixNano(), e.SiteID, e.Severity, e.Category, string(b)); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *Store) RecentErrors(ctx context.Context, site, severity, category string, from, to time.Time, limit int) ([]model.ErrorEvent, error) {
	if limit < 1 || limit > 50 || to.Before(from) || to.Sub(from) > 7*24*time.Hour {
		return nil, errors.New("invalid error query range")
	}
	from = s.retainedFrom(from, "errors")
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	rows, err := s.readDB.QueryContext(ctx, `SELECT payload_json FROM error_events WHERE timestamp_ns>=? AND timestamp_ns<=? AND (?='' OR site_id=?) AND (?='' OR severity=?) AND (?='' OR category=?) ORDER BY timestamp_ns DESC,id DESC LIMIT ?`, from.UnixNano(), to.UnixNano(), site, site, severity, severity, category, category, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ErrorEvent{}
	for rows.Next() {
		var b string
		var e model.ErrorEvent
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(b), &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

type RetentionStatus struct {
	DBBytes            int64      `json:"db_bytes"`
	WALBytes           int64      `json:"wal_bytes"`
	FreeBytes          uint64     `json:"free_bytes"`
	FreeBytesAvailable bool       `json:"free_bytes_available"`
	LowDisk            bool       `json:"low_disk"`
	LastPrune          *time.Time `json:"last_prune,omitempty"`
	From               *time.Time `json:"incident_from,omitempty"`
	To                 *time.Time `json:"incident_to,omitempty"`
	Error              string     `json:"error,omitempty"`
}
type PrunePreview struct {
	Incidents int64                   `json:"incidents"`
	Errors    int64                   `json:"errors"`
	Minutes   int64                   `json:"minutes"`
	Ranges    map[string]HistoryRange `json:"ranges"`
	Cutoffs   map[string]time.Time    `json:"cutoffs"`
}
type HistoryRange struct {
	From *time.Time `json:"from,omitempty"`
	To   *time.Time `json:"to,omitempty"`
}

func (s *Store) PrunePreview(ctx context.Context, r config.RetentionConfig, now time.Time) (PrunePreview, error) {
	r = r.Effective()
	p := PrunePreview{Ranges: map[string]HistoryRange{}, Cutoffs: map[string]time.Time{}}
	for _, v := range []struct {
		table, column string
		cutoff        int64
		count         *int64
		enabled       bool
	}{{"incidents", "timestamp_ns", now.Add(-r.Incidents.Duration).UnixNano(), &p.Incidents, r.Incidents.Duration > 0}, {"error_events", "timestamp_ns", now.Add(-r.Errors.Duration).UnixNano(), &p.Errors, true}, {"dashboard_minutes", "bucket_start", now.Add(-r.Minutes.Duration).Unix(), &p.Minutes, true}} {
		if v.enabled {
			var lo, hi *int64
			if err := s.readDB.QueryRowContext(ctx, fmt.Sprintf("SELECT COUNT(*),MIN(%s),MAX(%s) FROM %s WHERE %s < ?", v.column, v.column, v.table, v.column), v.cutoff).Scan(v.count, &lo, &hi); err != nil {
				return p, err
			}
			convert := func(n int64) time.Time {
				if v.column == "bucket_start" {
					return time.Unix(n, 0).UTC()
				}
				return time.Unix(0, n).UTC()
			}
			p.Cutoffs[v.table] = convert(v.cutoff)
			if lo != nil && hi != nil {
				from, to := convert(*lo), convert(*hi)
				p.Ranges[v.table] = HistoryRange{From: &from, To: &to}
			}
		}
	}
	return p, nil
}
func (s *Store) PruneHistory(ctx context.Context, r config.RetentionConfig, now time.Time) error {
	r = r.Effective()
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	for _, v := range []struct {
		table, column string
		cutoff        int64
		enabled       bool
	}{{"incidents", "timestamp_ns", now.Add(-r.Incidents.Duration).UnixNano(), r.Incidents.Duration > 0}, {"error_events", "timestamp_ns", now.Add(-r.Errors.Duration).UnixNano(), true}, {"dashboard_minutes", "bucket_start", now.Add(-r.Minutes.Duration).Unix(), true}} {
		if v.enabled {
			for batch := 0; batch < 20; batch++ {
				result, err := s.db.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s WHERE rowid IN (SELECT rowid FROM %s WHERE %s < ? ORDER BY %s LIMIT ?)", v.table, v.table, v.column, v.column), v.cutoff, r.BatchSize)
				if err != nil {
					return err
				}
				count, _ := result.RowsAffected()
				if count < int64(r.BatchSize) {
					break
				}
			}
		}
	}
	// Lookup tables otherwise retain every historical IP/site indefinitely.
	for _, v := range []struct{ table, key, reference string }{{"ips", "address", "ip_address"}, {"sites", "id", "site_id"}} {
		for batch := 0; batch < 20; batch++ {
			query := fmt.Sprintf("DELETE FROM %s WHERE %s IN (SELECT %s FROM %s WHERE NOT EXISTS(SELECT 1 FROM incidents WHERE incidents.%s=%s.%s) LIMIT ?)", v.table, v.key, v.key, v.table, v.reference, v.table, v.key)
			result, err := s.db.ExecContext(ctx, query, r.BatchSize)
			if err != nil {
				return err
			}
			count, _ := result.RowsAffected()
			if count < int64(r.BatchSize) {
				break
			}
		}
	}
	return s.SetState(ctx, "retention.last_prune", now.UTC().Format(time.RFC3339Nano))
}
func (s *Store) DiskStatus(ctx context.Context, minimum uint64) RetentionStatus {
	r := RetentionStatus{}
	if st, err := os.Stat(s.path); err == nil {
		r.DBBytes = st.Size()
	}
	if st, err := os.Stat(s.path + "-wal"); err == nil {
		r.WALBytes = st.Size()
	}
	var disk syscall.Statfs_t
	if err := syscall.Statfs(s.path, &disk); err == nil {
		r.FreeBytesAvailable = true
		r.FreeBytes = disk.Bavail * uint64(disk.Bsize)
		r.LowDisk = minimum > 0 && r.FreeBytes < minimum
	}
	if v, ok, err := s.GetState(ctx, "retention.last_prune"); err == nil && ok {
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			r.LastPrune = &t
		}
	}
	var lo, hi *int64
	if err := s.readDB.QueryRowContext(ctx, `SELECT (SELECT MIN(timestamp_ns) FROM incidents),(SELECT MAX(timestamp_ns) FROM incidents)`).Scan(&lo, &hi); err != nil {
		r.Error = "history range unavailable"
	} else if lo != nil && hi != nil {
		from, to := time.Unix(0, *lo), time.Unix(0, *hi)
		r.From = &from
		r.To = &to
	}
	return r
}
func (s *Store) Maintain(ctx context.Context, r config.RetentionConfig) {
	r = r.Effective()
	prune := func(now time.Time) {
		if err := s.PruneHistory(ctx, r, now); err != nil {
			fmt.Fprintln(s.diagnostics, "ReqSentry history pruning failed")
		}
	}
	prune(time.Now())
	ticker := time.NewTicker(r.Interval.Duration)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			prune(now)
		}
	}
}

func (s *Store) SetRetention(r config.RetentionConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.retention = r.Effective()
	if r.ErrorSamplesPerSecond > 0 {
		s.errorSampleLimit = r.ErrorSamplesPerSecond
	}
}
func PreviewPruneFile(ctx context.Context, path string, r config.RetentionConfig, now time.Time) (PrunePreview, error) {
	if _, err := os.Stat(path); err != nil {
		return PrunePreview{}, err
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return PrunePreview{}, err
	}
	u := (&url.URL{Scheme: "file", Path: absolute}).String() + "?mode=ro&_pragma=busy_timeout%3D1000"
	db, err := sql.Open("sqlite", u)
	if err != nil {
		return PrunePreview{}, err
	}
	defer db.Close()
	s := Store{readDB: db}
	return s.PrunePreview(ctx, r, now)
}

func (s *Store) retainedFrom(from time.Time, kind string) time.Time {
	s.mu.Lock()
	r := s.retention.Effective()
	s.mu.Unlock()
	age := r.Incidents.Duration
	if kind == "errors" {
		age = r.Errors.Duration
	}
	if kind == "minutes" {
		age = r.Minutes.Duration
	}
	cutoff := time.Now().Add(-age)
	if from.Before(cutoff) {
		return cutoff
	}
	return from
}
