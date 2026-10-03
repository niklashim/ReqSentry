// Package storage keeps incident history and small daemon state in SQLite.
package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
	_ "modernc.org/sqlite"
	"strings"
)

var ErrQueueFull = errors.New("SQLite incident queue full")
var ErrClosed = errors.New("SQLite store closed")

type Store struct {
	path              string
	errorQueue        chan model.ErrorEvent
	errorSampleLimit  int
	errorSampleSecond int64
	errorSampleCount  int
	db                *sql.DB
	readDB            *sql.DB
	diagnostics       io.Writer
	queue             chan writeRequest
	done              chan struct{}
	mu                sync.Mutex
	closed            bool
	retention         config.RetentionConfig
	opMu              sync.RWMutex
	operational       interface {
		Operational(string, string, uint64) error
	}
}

func (s *Store) SetOperationalSink(sink interface {
	Operational(string, string, uint64) error
}) {
	s.opMu.Lock()
	s.operational = sink
	s.opMu.Unlock()
}

type writeRequest struct {
	incident *model.Incident
	barrier  chan error
}

type Offset struct {
	Device uint64
	Inode  uint64
	Bytes  int64
}

func Open(path string, diagnostics io.Writer) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create SQLite directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open SQLite file: %w", err)
	}
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("protect SQLite file: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{"PRAGMA busy_timeout=5000", "PRAGMA journal_mode=WAL", "PRAGMA foreign_keys=ON"} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("SQLite setup %s: %w", pragma, err)
		}
	}
	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	readURL := (&url.URL{Scheme: "file", Path: absolutePath}).String() + "?mode=ro&_pragma=busy_timeout%3D1000"
	readDB, err := sql.Open("sqlite", readURL)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	readDB.SetMaxOpenConns(2)
	if err := readDB.Ping(); err != nil {
		_ = readDB.Close()
		_ = db.Close()
		return nil, fmt.Errorf("open SQLite dashboard reader: %w", err)
	}
	s := &Store{path: path, errorSampleLimit: 20, errorQueue: make(chan model.ErrorEvent, 128), db: db, readDB: readDB, diagnostics: diagnostics, queue: make(chan writeRequest, 256), done: make(chan struct{})}
	go s.run()
	return s, nil
}

func migrate(db *sql.DB) error {
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version > 6 {
		return fmt.Errorf("SQLite schema version %d is newer than supported version 6", version)
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if version == 0 {
		statements := []string{
			`CREATE TABLE IF NOT EXISTS sites (id TEXT PRIMARY KEY)`,
			`CREATE TABLE IF NOT EXISTS ips (address TEXT PRIMARY KEY)`,
			`CREATE TABLE IF NOT EXISTS incidents (
			id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, site_id TEXT NOT NULL,
			ip_address TEXT NOT NULL, score INTEGER NOT NULL, decision TEXT NOT NULL,
			ruleset_version INTEGER NOT NULL, payload_json TEXT NOT NULL,
			FOREIGN KEY(site_id) REFERENCES sites(id), FOREIGN KEY(ip_address) REFERENCES ips(address))`,
			`CREATE INDEX IF NOT EXISTS incident_time ON incidents(timestamp DESC)`,
			`CREATE TABLE IF NOT EXISTS traffic_windows (
			incident_id INTEGER PRIMARY KEY, window_start TEXT NOT NULL, window_end TEXT NOT NULL,
			requests INTEGER NOT NULL, peak_rps INTEGER NOT NULL,
			FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE)`,
			`CREATE TABLE IF NOT EXISTS system_state (
			key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)`,
			`CREATE TABLE IF NOT EXISTS watcher_offsets (
			path TEXT PRIMARY KEY, device TEXT NOT NULL, inode TEXT NOT NULL,
			byte_offset INTEGER NOT NULL, updated_at TEXT NOT NULL)`,
		}
		for _, statement := range statements {
			if _, err := tx.Exec(statement); err != nil {
				return fmt.Errorf("SQLite migration: %w", err)
			}
		}
	}
	if version < 2 {
		for _, statement := range []string{
			`CREATE TABLE IF NOT EXISTS incident_signals (incident_id INTEGER NOT NULL, code TEXT NOT NULL, PRIMARY KEY(incident_id,code), FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE)`,
			`CREATE INDEX IF NOT EXISTS incident_signals_code ON incident_signals(code,incident_id)`,
			`INSERT OR IGNORE INTO incident_signals(incident_id,code) SELECT incidents.id,json_extract(value,'$.code') FROM incidents,json_each(incidents.payload_json,'$.signals') WHERE json_extract(value,'$.code') IS NOT NULL`,
			`CREATE TABLE IF NOT EXISTS dashboard_minutes (bucket_start INTEGER NOT NULL, site_id TEXT NOT NULL, payload_json TEXT NOT NULL, PRIMARY KEY(bucket_start,site_id))`,
			`CREATE INDEX IF NOT EXISTS dashboard_minutes_site_time ON dashboard_minutes(site_id,bucket_start)`,
			`PRAGMA user_version=2`,
		} {
			if _, err := tx.Exec(statement); err != nil {
				return fmt.Errorf("SQLite migration v2: %w", err)
			}
		}
	}
	if version < 3 {
		rows, err := tx.Query(`PRAGMA table_info(incidents)`)
		if err != nil {
			return err
		}
		hasNanoseconds := false
		for rows.Next() {
			var position int
			var name, kind string
			var notNull, primary int
			var defaultValue sql.NullString
			if err := rows.Scan(&position, &name, &kind, &notNull, &defaultValue, &primary); err != nil {
				rows.Close()
				return err
			}
			if name == "timestamp_ns" {
				hasNanoseconds = true
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		if !hasNanoseconds {
			if _, err := tx.Exec(`ALTER TABLE incidents ADD COLUMN timestamp_ns INTEGER NOT NULL DEFAULT 0`); err != nil {
				return err
			}
		}
		rows, err = tx.Query(`SELECT id,timestamp FROM incidents WHERE timestamp_ns=0`)
		if err != nil {
			return err
		}
		type timestampRow struct {
			id    int64
			value string
		}
		var backfill []timestampRow
		for rows.Next() {
			var item timestampRow
			if err := rows.Scan(&item.id, &item.value); err != nil {
				rows.Close()
				return err
			}
			backfill = append(backfill, item)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		for _, item := range backfill {
			parsed, err := time.Parse(time.RFC3339Nano, item.value)
			if err != nil {
				return fmt.Errorf("invalid stored incident timestamp id=%d: %w", item.id, err)
			}
			if _, err := tx.Exec(`UPDATE incidents SET timestamp_ns=? WHERE id=?`, parsed.UnixNano(), item.id); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS incident_time_ns ON incidents(timestamp_ns DESC)`); err != nil {
			return err
		}
		if _, err := tx.Exec(`PRAGMA user_version=3`); err != nil {
			return err
		}
	}
	if version < 4 {
		for _, statement := range []string{
			`CREATE TABLE IF NOT EXISTS error_events(id INTEGER PRIMARY KEY,timestamp_ns INTEGER NOT NULL,site_id TEXT NOT NULL,severity TEXT NOT NULL,category TEXT NOT NULL,payload_json TEXT NOT NULL)`,
			`CREATE INDEX IF NOT EXISTS error_events_site_time ON error_events(site_id,timestamp_ns DESC)`,
			`CREATE INDEX IF NOT EXISTS error_events_time ON error_events(timestamp_ns DESC)`,
			`PRAGMA user_version=4`,
		} {
			if _, err := tx.Exec(statement); err != nil {
				return err
			}
		}
	}
	if version < 5 {
		has, err := hasColumn(tx, "incidents", "event_id")
		if err != nil {
			return err
		}
		if !has {
			if _, err := tx.Exec(`ALTER TABLE incidents ADD COLUMN event_id TEXT`); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS incident_event_id ON incidents(event_id) WHERE event_id IS NOT NULL`); err != nil {
			return err
		}
		if _, err := tx.Exec(`PRAGMA user_version=5`); err != nil {
			return err
		}
	}
	if version < 6 {
		for _, statement := range []string{
			`CREATE TABLE IF NOT EXISTS incident_requests(incident_id INTEGER NOT NULL,sample_index INTEGER NOT NULL,timestamp_ns INTEGER NOT NULL,site_id TEXT NOT NULL,ip_address TEXT NOT NULL,method TEXT NOT NULL,status INTEGER NOT NULL,search_text TEXT NOT NULL,payload_json TEXT NOT NULL,PRIMARY KEY(incident_id,sample_index),FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE)`,
			`CREATE INDEX IF NOT EXISTS incident_requests_site_time ON incident_requests(site_id,timestamp_ns DESC)`,
			`CREATE INDEX IF NOT EXISTS incident_requests_time ON incident_requests(timestamp_ns DESC)`,
			`CREATE INDEX IF NOT EXISTS incident_ip_time ON incidents(ip_address,timestamp_ns DESC)`,
			`CREATE INDEX IF NOT EXISTS incident_site_time ON incidents(site_id,timestamp_ns DESC)`,
			`PRAGMA user_version=6`,
		} {
			if _, err := tx.Exec(statement); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// WriteIncident queues an immutable snapshot; database work happens in batches
// on a worker and never on the log watcher path.
func (s *Store) WriteIncident(_ context.Context, incident model.Incident) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	select {
	case s.queue <- writeRequest{incident: &incident}:
		return nil
	default:
		return ErrQueueFull
	}
}

// Flush waits until all previously queued incidents have committed. It is
// used before clean watcher offsets advance on shutdown.
func (s *Store) Flush(ctx context.Context) error {
	barrier := make(chan error, 1)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	select {
	case s.queue <- writeRequest{barrier: barrier}:
		s.mu.Unlock()
	case <-ctx.Done():
		s.mu.Unlock()
		return ctx.Err()
	}
	select {
	case err := <-barrier:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Store) run() {
	defer close(s.done)
	batch := make([]model.Incident, 0, 64)
	errorBatch := make([]model.ErrorEvent, 0, 64)
	errorQueue := s.errorQueue
	drainErrors := func() {
		count := len(errorQueue)
		for i := 0; i < count; i++ {
			select {
			case e := <-errorQueue:
				errorBatch = append(errorBatch, e)
			default:
				return
			}
		}
	}
	var priorError error
	var consecutive uint64
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	flush := func() error {
		if len(batch) == 0 && len(errorBatch) == 0 {
			return nil
		}
		var err error
		if len(batch) > 0 {
			err = s.insertBatch(batch)
		}
		if len(errorBatch) > 0 {
			err = errors.Join(err, s.insertErrors(errorBatch))
			errorBatch = errorBatch[:0]
		}
		if err != nil {
			consecutive++
			priorError = errors.Join(priorError, err)
			fmt.Fprintf(s.diagnostics, "ReqSentry SQLite incident batch failed count=%d: %v\n", len(batch), err)
			s.opMu.RLock()
			sink := s.operational
			s.opMu.RUnlock()
			if sink != nil {
				_ = sink.Operational("sqlite", err.Error(), consecutive)
			}
		} else {
			consecutive = 0
		}
		batch = batch[:0]
		return err
	}
	for {
		select {
		case e := <-errorQueue:
			errorBatch = append(errorBatch, e)
			if len(errorBatch) >= 64 {
				_ = flush()
			}
		case request, ok := <-s.queue:
			if !ok {
				drainErrors()
				_ = flush()
				return
			}
			if request.barrier != nil {
				drainErrors()
				_ = flush()
				request.barrier <- priorError
				priorError = nil
				continue
			}
			batch = append(batch, *request.incident)
			if len(batch) == cap(batch) {
				_ = flush()
			}
		case <-ticker.C:
			_ = flush()
		}
	}
}

func (s *Store) insertBatch(batch []model.Incident) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, incident := range batch {
		if len(incident.RequestSamples) > model.MaxRequestSamples {
			incident.RequestSamples = incident.RequestSamples[:model.MaxRequestSamples]
		}
		payload, err := json.Marshal(incident)
		if err != nil {
			return err
		}
		ip := incident.ClientIP.Unmap().String()
		if _, err := tx.Exec(`INSERT OR IGNORE INTO sites(id) VALUES(?)`, incident.SiteID); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO ips(address) VALUES(?)`, ip); err != nil {
			return err
		}
		result, err := tx.Exec(`INSERT OR IGNORE INTO incidents(timestamp,timestamp_ns,site_id,ip_address,score,decision,ruleset_version,payload_json,event_id) VALUES(?,?,?,?,?,?,?,?,?)`,
			incident.Timestamp.UTC().Format(time.RFC3339Nano), incident.Timestamp.UnixNano(), incident.SiteID, ip, incident.Score, incident.Decision, incident.RulesetVersion, string(payload), nullableEventID(incident.EventID))
		if err != nil {
			return err
		}
		if count, _ := result.RowsAffected(); count == 0 {
			continue
		}
		id, err := result.LastInsertId()
		if err != nil {
			return err
		}
		for _, signal := range incident.Signals {
			if _, err := tx.Exec(`INSERT OR IGNORE INTO incident_signals(incident_id,code) VALUES(?,?)`, id, signal.Code); err != nil {
				return err
			}
		}
		for index, sample := range incident.RequestSamples {
			payload, err := json.Marshal(sample)
			if err != nil {
				return err
			}
			search := strings.Join([]string{sample.Method, sample.Path, sample.RequestID, sample.TraceID, sample.ClientIP.String()}, " ")
			if _, err := tx.Exec(`INSERT INTO incident_requests(incident_id,sample_index,timestamp_ns,site_id,ip_address,method,status,search_text,payload_json) VALUES(?,?,?,?,?,?,?,?,?)`, id, index, sample.Timestamp.UnixNano(), sample.SiteID, sample.ClientIP.Unmap().String(), sample.Method, sample.Status, search, string(payload)); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(`INSERT INTO traffic_windows(incident_id,window_start,window_end,requests,peak_rps) VALUES(?,?,?,?,?)`,
			id, incident.WindowStart.UTC().Format(time.RFC3339Nano), incident.WindowEnd.UTC().Format(time.RFC3339Nano), incident.Requests, incident.PeakRPS); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) RecentIncidents(ctx context.Context, limit int) ([]model.Incident, error) {
	if limit < 1 || limit > 1000 {
		return nil, errors.New("incident limit must be between 1 and 1000")
	}
	rows, err := s.readDB.QueryContext(ctx, `SELECT payload_json FROM incidents WHERE timestamp_ns>=? ORDER BY id DESC LIMIT ?`, s.retainedFrom(time.Time{}, "incidents").UnixNano(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []model.Incident
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var incident model.Incident
		if err := json.Unmarshal([]byte(payload), &incident); err != nil {
			return nil, err
		}
		result = append(result, incident)
	}
	return result, rows.Err()
}

func (s *Store) SetState(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO system_state(key,value,updated_at) VALUES(?,?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`, key, value, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) GetState(ctx context.Context, key string) (string, bool, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM system_state WHERE key=?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return value, err == nil, err
}

func (s *Store) SaveOffset(ctx context.Context, path string, offset Offset) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO watcher_offsets(path,device,inode,byte_offset,updated_at) VALUES(?,?,?,?,?)
		ON CONFLICT(path) DO UPDATE SET device=excluded.device,inode=excluded.inode,byte_offset=excluded.byte_offset,updated_at=excluded.updated_at`,
		path, strconv.FormatUint(offset.Device, 10), strconv.FormatUint(offset.Inode, 10), offset.Bytes, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) LoadOffset(ctx context.Context, path string) (Offset, bool, error) {
	var device, inode string
	var offset Offset
	err := s.db.QueryRowContext(ctx, `SELECT device,inode,byte_offset FROM watcher_offsets WHERE path=?`, path).Scan(&device, &inode, &offset.Bytes)
	if errors.Is(err, sql.ErrNoRows) {
		return Offset{}, false, nil
	}
	if err != nil {
		return Offset{}, false, err
	}
	if offset.Device, err = strconv.ParseUint(device, 10, 64); err != nil {
		return Offset{}, false, err
	}
	if offset.Inode, err = strconv.ParseUint(inode, 10, 64); err != nil {
		return Offset{}, false, err
	}
	return offset, true, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.queue)
	}
	s.mu.Unlock()
	<-s.done
	readErr := s.readDB.Close()
	return errors.Join(readErr, s.db.Close())
}

func nullableEventID(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func hasColumn(tx *sql.Tx, table, column string) (bool, error) {
	rows, err := tx.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var id, required, primary int
		var name, kind string
		var defaultValue sql.NullString
		if err := rows.Scan(&id, &name, &kind, &required, &defaultValue, &primary); err != nil {
			return false, err
		}
		if name == column {
			found = true
		}
	}
	return found, rows.Err()
}
