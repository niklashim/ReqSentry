package storage

import (
	"context"
	"errors"
	"time"
)

type ErrorBucket struct {
	At     time.Time `json:"at"`
	Errors uint64    `json:"errors"`
}

func (s *Store) ErrorHistory(ctx context.Context, site string, from, to time.Time, bucketSeconds int64) ([]ErrorBucket, error) {
	if to.Before(from) || to.Sub(from) > 7*24*time.Hour || bucketSeconds < 60 {
		return nil, errors.New("invalid error history range")
	}
	from = s.retainedFrom(from, "errors")
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	rows, err := s.readDB.QueryContext(ctx, `SELECT (timestamp_ns/1000000000/?)*?,COUNT(*) FROM error_events WHERE timestamp_ns>=? AND timestamp_ns<=? AND (?='' OR site_id=?) GROUP BY 1 ORDER BY 1 LIMIT 121`, bucketSeconds, bucketSeconds, from.UnixNano(), to.UnixNano(), site, site)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ErrorBucket{}
	for rows.Next() {
		var at int64
		var b ErrorBucket
		if err := rows.Scan(&at, &b.Errors); err != nil {
			return nil, err
		}
		b.At = time.Unix(at, 0).UTC()
		out = append(out, b)
	}
	return out, rows.Err()
}
