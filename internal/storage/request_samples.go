package storage

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/niklashim/ReqSentry/internal/model"
	"strings"
	"time"
)

type RequestSampleFilter struct {
	From, To                        time.Time
	Site, Server, IP, Method, Query string
	Status                          int
	IncidentID                      int64
	Limit, Offset                   int
}
type StoredRequestSample struct {
	IncidentID int64               `json:"incident_id"`
	Server     string              `json:"server"`
	Score      int                 `json:"score"`
	Decision   model.Decision      `json:"decision"`
	Sample     model.RequestSample `json:"sample"`
}

func (s *Store) SearchRequestSamples(ctx context.Context, f RequestSampleFilter) ([]StoredRequestSample, int, error) {
	if f.Limit < 1 || f.Limit > 100 || f.Offset < 0 || f.Offset > 10000 || f.To.Before(f.From) || f.To.Sub(f.From) > 366*24*time.Hour || len(f.Query) > 256 || len(f.Site) > 128 || len(f.Server) > 128 || len(f.IP) > 64 || len(f.Method) > 32 || (f.Status != 0 && (f.Status < 100 || f.Status > 599)) || f.IncidentID < 0 {
		return nil, 0, errors.New("invalid request sample filter")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	conditions := []string{"i.timestamp_ns>=?", "i.timestamp_ns<=?"}
	args := []any{s.retainedFrom(f.From, "incidents").UnixNano(), f.To.UnixNano()}
	for _, v := range []struct{ column, value string }{{"r.site_id", f.Site}, {"r.ip_address", f.IP}, {"r.method", f.Method}, {"json_extract(i.payload_json,'$.server')", f.Server}} {
		if v.value != "" {
			conditions = append(conditions, v.column+"=?")
			args = append(args, v.value)
		}
	}
	if f.Status != 0 {
		conditions = append(conditions, "r.status=?")
		args = append(args, f.Status)
	}
	if f.IncidentID != 0 {
		conditions = append(conditions, "i.id=?")
		args = append(args, f.IncidentID)
	}
	if f.Query != "" {
		conditions = append(conditions, "instr(lower(r.search_text),lower(?))>0")
		args = append(args, f.Query)
	}
	where := " FROM incident_requests r JOIN incidents i ON i.id=r.incident_id WHERE " + strings.Join(conditions, " AND ")
	var count int
	if err := s.readDB.QueryRowContext(ctx, "SELECT COUNT(*)"+where, args...).Scan(&count); err != nil {
		return nil, 0, err
	}
	args = append(args, f.Limit, f.Offset)
	rows, err := s.readDB.QueryContext(ctx, "SELECT i.id,json_extract(i.payload_json,'$.server'),i.score,i.decision,r.payload_json"+where+" ORDER BY i.id DESC,r.sample_index DESC LIMIT ? OFFSET ?", args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []StoredRequestSample{}
	for rows.Next() {
		var v StoredRequestSample
		var payload string
		if err := rows.Scan(&v.IncidentID, &v.Server, &v.Score, &v.Decision, &payload); err != nil {
			return nil, 0, err
		}
		if err := json.Unmarshal([]byte(payload), &v.Sample); err != nil {
			return nil, 0, err
		}
		out = append(out, v)
	}
	return out, count, rows.Err()
}
