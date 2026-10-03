package storage

import (
	"context"
	"strconv"
	"time"
)

func (s *Store) SaveOffsets(ctx context.Context, offsets map[string]Offset) error {
	if err := s.beginDurable(ctx); err != nil {
		return err
	}
	defer s.endDurable()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writeLoss != nil {
		return s.writeLoss
	}
	if s.workerError != nil {
		return s.workerError
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for path, o := range offsets {
		if _, err := tx.ExecContext(ctx, `INSERT INTO watcher_offsets(path,device,inode,byte_offset,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET device=excluded.device,inode=excluded.inode,byte_offset=excluded.byte_offset,updated_at=excluded.updated_at`, path, strconv.FormatUint(o.Device, 10), strconv.FormatUint(o.Inode, 10), o.Bytes, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) OffsetUpdatedAt(ctx context.Context, path string) (time.Time, error) {
	var value string
	err := s.readDB.QueryRowContext(ctx, `SELECT updated_at FROM watcher_offsets WHERE path=?`, path).Scan(&value)
	if err != nil {
		return time.Time{}, err
	}
	return time.Parse(time.RFC3339Nano, value)
}
