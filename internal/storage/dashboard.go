package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/niklashim/ReqSentry/internal/model"
)

type HistorySample struct {
	At                time.Time `json:"at"`
	BucketMinutes     int       `json:"bucket_minutes,omitempty"`
	Missing           bool      `json:"missing,omitempty"`
	SiteID            string    `json:"site_id"`
	Requests          uint64    `json:"requests"`
	TrackedUniqueIPs  int       `json:"tracked_unique_ips"`
	Status2xx         uint64    `json:"status_2xx"`
	Status301         uint64    `json:"status_301"`
	Status302         uint64    `json:"status_302"`
	Status403         uint64    `json:"status_403"`
	Status404         uint64    `json:"status_404"`
	Status5xx         uint64    `json:"status_5xx"`
	Incidents         *int      `json:"incidents,omitempty"`
	WouldBlock        *int      `json:"would_block,omitempty"`
	CPUPercent        *float64  `json:"cpu_percent,omitempty"`
	Load1             *float64  `json:"load_1m,omitempty"`
	MemoryUsedPercent *float64  `json:"memory_used_percent,omitempty"`
	PHPActive         *int64    `json:"php_active,omitempty"`
	PHPIdle           *int64    `json:"php_idle,omitempty"`
	PHPListenQueue    *int64    `json:"php_listen_queue,omitempty"`
	Complete          bool      `json:"complete"`
}

type MinuteIncidentCounts struct {
	Incidents  int
	WouldBlock int
}

// IncidentMinuteCounts uses the indexed event timestamp. Call Flush first when
// the caller requires every incident already queued at the minute boundary.
func (s *Store) IncidentMinuteCounts(ctx context.Context, minute time.Time) (MinuteIncidentCounts, map[string]MinuteIncidentCounts, error) {
	start := minute.UTC().Truncate(time.Minute).UnixNano()
	end := minute.UTC().Truncate(time.Minute).Add(time.Minute).UnixNano()
	rows, err := s.readDB.QueryContext(ctx, `SELECT site_id,COUNT(*),SUM(CASE WHEN decision='WOULD_BLOCK' THEN 1 ELSE 0 END)
		FROM incidents WHERE timestamp_ns>=? AND timestamp_ns<? GROUP BY site_id`, start, end)
	if err != nil {
		return MinuteIncidentCounts{}, nil, err
	}
	defer rows.Close()
	bySite := make(map[string]MinuteIncidentCounts)
	var total MinuteIncidentCounts
	for rows.Next() {
		var site string
		var item MinuteIncidentCounts
		if err := rows.Scan(&site, &item.Incidents, &item.WouldBlock); err != nil {
			return MinuteIncidentCounts{}, nil, err
		}
		bySite[site] = item
		total.Incidents += item.Incidents
		total.WouldBlock += item.WouldBlock
	}
	return total, bySite, rows.Err()
}

func (s *Store) SaveDashboardMinutes(ctx context.Context, samples []HistorySample) error {
	if len(samples) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, sample := range samples {
		payload, err := json.Marshal(sample)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO dashboard_minutes(bucket_start,site_id,payload_json) VALUES(?,?,?)
			ON CONFLICT(bucket_start,site_id) DO UPDATE SET payload_json=excluded.payload_json`, sample.At.UTC().Truncate(time.Minute).Unix(), sample.SiteID, string(payload))
		if err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM dashboard_minutes WHERE bucket_start < ?`, time.Now().Add(-7*24*time.Hour).UTC().Unix())
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DashboardHistory(ctx context.Context, site string, from, to time.Time, maxPoints int) ([]HistorySample, error) {
	if maxPoints < 1 || maxPoints > 500 || to.Before(from) || to.Sub(from) > 7*24*time.Hour {
		return nil, errors.New("dashboard history range or point limit invalid")
	}
	start := from.UTC().Truncate(time.Minute)
	end := to.UTC().Truncate(time.Minute)
	minutes := int(end.Sub(start)/time.Minute) + 1
	step := (minutes + maxPoints - 1) / maxPoints
	if step < 1 {
		step = 1
	}
	rows, err := s.readDB.QueryContext(ctx, `SELECT payload_json FROM dashboard_minutes WHERE site_id=? AND bucket_start>=? AND bucket_start<=? ORDER BY bucket_start LIMIT 10081`, site, start.Unix(), end.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]HistorySample, (minutes+step-1)/step)
	seen := make([]int, len(result))
	incidentComplete := make([]bool, len(result))
	for i := range result {
		result[i] = HistorySample{At: start.Add(time.Duration(i*step) * time.Minute), SiteID: site, BucketMinutes: min(step, minutes-i*step), Complete: true, Missing: true}
		incidentComplete[i] = true
	}
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var item HistorySample
		if err := json.Unmarshal([]byte(payload), &item); err != nil {
			return nil, err
		}
		index := int(item.At.UTC().Truncate(time.Minute).Sub(start)/time.Minute) / step
		if index < 0 || index >= len(result) {
			continue
		}
		bucket := &result[index]
		seen[index]++
		bucket.Missing = false
		bucket.Complete = bucket.Complete && item.Complete
		bucket.Requests += item.Requests
		bucket.Status2xx += item.Status2xx
		bucket.Status301 += item.Status301
		bucket.Status302 += item.Status302
		bucket.Status403 += item.Status403
		bucket.Status404 += item.Status404
		bucket.Status5xx += item.Status5xx
		if item.TrackedUniqueIPs > bucket.TrackedUniqueIPs {
			bucket.TrackedUniqueIPs = item.TrackedUniqueIPs
		}
		if item.Incidents == nil || item.WouldBlock == nil {
			incidentComplete[index] = false
		} else {
			if bucket.Incidents == nil {
				bucket.Incidents = new(int)
				bucket.WouldBlock = new(int)
			}
			*bucket.Incidents += *item.Incidents
			*bucket.WouldBlock += *item.WouldBlock
		}
		// Resource measurements represent the latest available sample in the bucket.
		if item.CPUPercent != nil {
			bucket.CPUPercent = item.CPUPercent
		}
		if item.Load1 != nil {
			bucket.Load1 = item.Load1
		}
		if item.MemoryUsedPercent != nil {
			bucket.MemoryUsedPercent = item.MemoryUsedPercent
		}
		if item.PHPActive != nil {
			bucket.PHPActive = item.PHPActive
		}
		if item.PHPIdle != nil {
			bucket.PHPIdle = item.PHPIdle
		}
		if item.PHPListenQueue != nil {
			bucket.PHPListenQueue = item.PHPListenQueue
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	anySample := false
	for i := range result {
		anySample = anySample || seen[i] > 0
		if seen[i] != result[i].BucketMinutes || !result[i].Complete {
			result[i].Missing = true
		}
		if !incidentComplete[i] || result[i].Missing {
			result[i].Incidents = nil
			result[i].WouldBlock = nil
		}
	}
	if !anySample {
		return nil, nil
	}
	return result, nil
}

type IncidentFilter struct {
	From     time.Time
	To       time.Time
	Site     string
	IP       string
	Decision model.Decision
	MinScore int
	MaxScore int
	Signal   string
	Limit    int
	Offset   int
}

type StoredIncident struct {
	ID       int64          `json:"id"`
	Incident model.Incident `json:"incident"`
}

func (s *Store) SearchIncidents(ctx context.Context, filter IncidentFilter) ([]StoredIncident, int, error) {
	if filter.Limit < 1 || filter.Limit > 100 || filter.Offset < 0 || filter.Offset > 10000 || filter.MinScore < 0 || filter.MaxScore > 100 || filter.MinScore > filter.MaxScore || filter.To.Before(filter.From) || filter.To.Sub(filter.From) > 7*24*time.Hour {
		return nil, 0, errors.New("invalid incident filter")
	}
	var conditions []string
	var args []any
	if !filter.From.IsZero() {
		conditions = append(conditions, "timestamp_ns >= ?")
		args = append(args, filter.From.UnixNano())
	}
	if !filter.To.IsZero() {
		conditions = append(conditions, "timestamp_ns <= ?")
		args = append(args, filter.To.UnixNano())
	}
	if filter.Site != "" {
		conditions = append(conditions, "site_id = ?")
		args = append(args, filter.Site)
	}
	if filter.IP != "" {
		conditions = append(conditions, "ip_address = ?")
		args = append(args, filter.IP)
	}
	if filter.Decision != "" {
		conditions = append(conditions, "decision = ?")
		args = append(args, string(filter.Decision))
	}
	conditions = append(conditions, "score >= ?", "score <= ?")
	args = append(args, filter.MinScore, filter.MaxScore)
	if filter.Signal != "" {
		conditions = append(conditions, "EXISTS (SELECT 1 FROM incident_signals WHERE incident_id=incidents.id AND code=?)")
		args = append(args, filter.Signal)
	}
	where := " WHERE " + strings.Join(conditions, " AND ")
	var count int
	if err := s.readDB.QueryRowContext(ctx, "SELECT COUNT(*) FROM incidents"+where, args...).Scan(&count); err != nil {
		return nil, 0, err
	}
	listArgs := append(append([]any(nil), args...), filter.Limit, filter.Offset)
	rows, err := s.readDB.QueryContext(ctx, "SELECT id,payload_json FROM incidents"+where+" ORDER BY id DESC LIMIT ? OFFSET ?", listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	result := make([]StoredIncident, 0)
	for rows.Next() {
		var item StoredIncident
		var payload string
		if err := rows.Scan(&item.ID, &payload); err != nil {
			return nil, 0, err
		}
		if err := json.Unmarshal([]byte(payload), &item.Incident); err != nil {
			return nil, 0, fmt.Errorf("decode incident %d: %w", item.ID, err)
		}
		result = append(result, item)
	}
	return result, count, rows.Err()
}

func (s *Store) IncidentByID(ctx context.Context, id int64) (StoredIncident, bool, error) {
	if id < 1 {
		return StoredIncident{}, false, errors.New("incident ID must be positive")
	}
	var item StoredIncident
	var payload string
	err := s.readDB.QueryRowContext(ctx, `SELECT id,payload_json FROM incidents WHERE id=?`, id).Scan(&item.ID, &payload)
	if errors.Is(err, sql.ErrNoRows) {
		return StoredIncident{}, false, nil
	}
	if err != nil {
		return StoredIncident{}, false, err
	}
	if err := json.Unmarshal([]byte(payload), &item.Incident); err != nil {
		return StoredIncident{}, false, err
	}
	return item, true, nil
}
