package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/gasserp/probing/classifier"
)

const MaxRecoveryObservations = 100_000

func (s *Store) SSHFailuresSince(
	ctx context.Context,
	since time.Time,
	limit int,
) ([]classifier.SSHFailure, error) {
	if since.Location() != time.UTC {
		return nil, errors.New("recovery start time must be UTC")
	}
	if limit < 1 || limit > MaxRecoveryObservations {
		return nil, fmt.Errorf("recovery limit must be between 1 and %d", MaxRecoveryObservations)
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT event_id, observed_at, source_ip, username
		FROM observations
		WHERE kind = 'ssh_auth_failure'
			AND (
				observed_unix_seconds > ?
				OR (
					observed_unix_seconds = ?
					AND observed_nanosecond >= ?
				)
			)
		ORDER BY observed_unix_seconds, observed_nanosecond, event_id
		LIMIT ?
	`, since.Unix(), since.Unix(), since.Nanosecond(), limit+1)
	if err != nil {
		return nil, fmt.Errorf("query SSH recovery observations: %w", err)
	}
	defer rows.Close()

	failures := make([]classifier.SSHFailure, 0, min(limit, 1024))
	for rows.Next() {
		if len(failures) == limit {
			return nil, fmt.Errorf("SSH recovery exceeds the limit of %d observations", limit)
		}
		var failure classifier.SSHFailure
		var observedAt, sourceIP string
		if err := rows.Scan(&failure.EventID, &observedAt, &sourceIP, &failure.Username); err != nil {
			return nil, fmt.Errorf("scan SSH recovery observation: %w", err)
		}
		var err error
		failure.ObservedAt, err = time.Parse(time.RFC3339Nano, observedAt)
		if err != nil {
			return nil, fmt.Errorf("parse SSH recovery timestamp: %w", err)
		}
		failure.SourceIP, err = netip.ParseAddr(sourceIP)
		if err != nil {
			return nil, fmt.Errorf("parse SSH recovery address: %w", err)
		}
		failures = append(failures, failure)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate SSH recovery observations: %w", err)
	}
	return failures, nil
}
