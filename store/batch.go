package store

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gasserp/probing/protocol"
)

const (
	DefaultMaxBatchObservations = 10_000
	MaxPendingBatches           = 128
)

var ErrNoPromotedObservations = errors.New("no promoted observations are ready")

type BatchConfig struct {
	SourceID          string
	SourceEpoch       string
	ClassifierVersion string
	KeyID             string
	PrivateKey        ed25519.PrivateKey
	MaxObservations   int
}

type PendingBatch struct {
	Sequence    string
	PayloadHash string
	Envelope    []byte
}

type storedObservation struct {
	eventID    string
	kind       protocol.ObservationKind
	observedAt time.Time
	sourceIP   string
	value      string
	ruleIDs    []string
}

func (s *Store) CreatePendingBatch(
	ctx context.Context,
	config BatchConfig,
	createdAt time.Time,
	watermark time.Time,
) (PendingBatch, error) {
	if createdAt.Location() != time.UTC {
		return PendingBatch{}, errors.New("batch creation time must be UTC")
	}
	if watermark.Location() != time.UTC || watermark.After(createdAt) {
		return PendingBatch{}, errors.New("batch watermark must be UTC and not after creation time")
	}
	maxObservations := config.MaxObservations
	if maxObservations == 0 {
		maxObservations = DefaultMaxBatchObservations
	}
	if maxObservations < 1 || maxObservations > DefaultMaxBatchObservations {
		return PendingBatch{}, fmt.Errorf("max observations must be between 1 and %d", DefaultMaxBatchObservations)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PendingBatch{}, fmt.Errorf("begin batch transaction: %w", err)
	}
	defer tx.Rollback()

	sequence, previousHash, err := ensureBatchState(ctx, tx, config)
	if err != nil {
		return PendingBatch{}, err
	}
	var pendingCount int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM batches WHERE published_commit_sha IS NULL
	`).Scan(&pendingCount); err != nil {
		return PendingBatch{}, fmt.Errorf("count pending batches: %w", err)
	}
	if pendingCount >= MaxPendingBatches {
		return PendingBatch{}, fmt.Errorf("pending batch limit of %d reached", MaxPendingBatches)
	}
	observations, err := selectBatchObservations(ctx, tx, maxObservations, watermark)
	if err != nil {
		return PendingBatch{}, err
	}
	if len(observations) == 0 {
		return PendingBatch{}, ErrNoPromotedObservations
	}

	var batch protocol.SignedBatch
	var payloadHash string
	used := observations
	for {
		payload := buildPayload(config, sequence, previousHash, createdAt, used)
		encodedPayload, marshalErr := json.Marshal(payload)
		if marshalErr != nil {
			return PendingBatch{}, fmt.Errorf("encode batch payload: %w", marshalErr)
		}
		if len(encodedPayload) > protocol.MaxEncodedBatchBytes {
			if len(used) == 1 {
				return PendingBatch{}, errors.New("single-observation batch exceeds the encoded size limit")
			}
			used = used[:len(used)/2]
			continue
		}
		batch, err = protocol.SignBatch(payload, config.KeyID, config.PrivateKey)
		if err != nil {
			return PendingBatch{}, fmt.Errorf("build batch: %w", err)
		}
		payloadHash, err = protocol.PayloadHash(payload)
		if err != nil {
			return PendingBatch{}, err
		}
		break
	}

	envelope, err := json.Marshal(batch)
	if err != nil {
		return PendingBatch{}, fmt.Errorf("encode signed batch: %w", err)
	}
	if len(envelope) > protocol.MaxEncodedEnvelopeBytes {
		return PendingBatch{}, errors.New("signed batch envelope exceeds the encoded size limit")
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO batches (sequence, payload_hash, envelope, created_at)
		VALUES (?, ?, ?, ?)
	`, sequence, payloadHash, envelope, createdAt.Format(time.RFC3339Nano)); err != nil {
		return PendingBatch{}, fmt.Errorf("store pending batch: %w", err)
	}
	for _, observation := range used {
		if _, err := tx.ExecContext(ctx, `
			UPDATE observations
			SET batch_sequence = ?
			WHERE event_id = ? AND batch_sequence IS NULL
		`, sequence, observation.eventID); err != nil {
			return PendingBatch{}, fmt.Errorf("assign observation to batch: %w", err)
		}
	}
	nextSequence, err := incrementSequence(sequence)
	if err != nil {
		return PendingBatch{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE batch_state
		SET next_sequence = ?, previous_hash = ?
		WHERE singleton = 1
	`, nextSequence, payloadHash); err != nil {
		return PendingBatch{}, fmt.Errorf("advance batch state: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return PendingBatch{}, fmt.Errorf("commit pending batch: %w", err)
	}

	return PendingBatch{
		Sequence:    sequence,
		PayloadHash: payloadHash,
		Envelope:    envelope,
	}, nil
}

func (s *Store) NextPendingBatch(ctx context.Context) (PendingBatch, bool, error) {
	var batch PendingBatch
	err := s.db.QueryRowContext(ctx, `
		SELECT sequence, payload_hash, envelope
		FROM batches
		WHERE published_commit_sha IS NULL
		ORDER BY id
		LIMIT 1
	`).Scan(&batch.Sequence, &batch.PayloadHash, &batch.Envelope)
	if errors.Is(err, sql.ErrNoRows) {
		return PendingBatch{}, false, nil
	}
	if err != nil {
		return PendingBatch{}, false, fmt.Errorf("query next pending batch: %w", err)
	}
	return batch, true, nil
}

func (s *Store) MarkBatchPublished(ctx context.Context, sequence, commitSHA string) error {
	if !validGitObjectID(commitSHA) {
		return errors.New("published commit SHA must be a lowercase 40- or 64-character hex object ID")
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE batches
		SET published_commit_sha = ?
		WHERE sequence = ? AND published_commit_sha IS NULL
	`, commitSHA, sequence)
	if err != nil {
		return fmt.Errorf("mark batch published: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect published batch update: %w", err)
	}
	if rows != 1 {
		return errors.New("pending batch sequence was not found")
	}
	return nil
}

func ensureBatchState(
	ctx context.Context,
	tx *sql.Tx,
	config BatchConfig,
) (string, string, error) {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO batch_state (
			singleton, source_id, source_epoch, next_sequence, previous_hash
		) VALUES (1, ?, ?, '0', '')
		ON CONFLICT(singleton) DO NOTHING
	`, config.SourceID, config.SourceEpoch); err != nil {
		return "", "", fmt.Errorf("initialize batch state: %w", err)
	}

	var sourceID, sourceEpoch, sequence, previousHash string
	if err := tx.QueryRowContext(ctx, `
		SELECT source_id, source_epoch, next_sequence, previous_hash
		FROM batch_state
		WHERE singleton = 1
	`).Scan(&sourceID, &sourceEpoch, &sequence, &previousHash); err != nil {
		return "", "", fmt.Errorf("read batch state: %w", err)
	}
	if sourceID != config.SourceID || sourceEpoch != config.SourceEpoch {
		return "", "", errors.New("batch source identity does not match durable state")
	}
	return sequence, previousHash, nil
}

func selectBatchObservations(
	ctx context.Context,
	tx *sql.Tx,
	limit int,
	watermark time.Time,
) ([]storedObservation, error) {
	var earliestValue string
	err := tx.QueryRowContext(ctx, `
		SELECT observed_at
		FROM observations
		WHERE promoted = 1
			AND batch_sequence IS NULL
			AND (
				observed_unix_seconds < ?
				OR (
					observed_unix_seconds = ?
					AND observed_nanosecond < ?
				)
			)
		ORDER BY observed_unix_seconds, observed_nanosecond, event_id
		LIMIT 1
	`, watermark.Unix(), watermark.Unix(), watermark.Nanosecond()).Scan(&earliestValue)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find earliest batch observation: %w", err)
	}
	earliest, err := time.Parse(time.RFC3339Nano, earliestValue)
	if err != nil {
		return nil, fmt.Errorf("parse earliest batch observation: %w", err)
	}
	endLimit := earliest.Truncate(time.Hour).Add(protocol.MaxObservationWindow)

	rows, err := tx.QueryContext(ctx, `
		SELECT event_id, kind, observed_at, source_ip,
			CASE WHEN kind = 'ssh_auth_failure' THEN username ELSE path END,
			rule_ids
		FROM observations
		WHERE promoted = 1
			AND batch_sequence IS NULL
			AND (
				observed_unix_seconds < ?
				OR (
					observed_unix_seconds = ?
					AND observed_nanosecond < ?
				)
			)
			AND (
				observed_unix_seconds < ?
				OR (
					observed_unix_seconds = ?
					AND observed_nanosecond < ?
				)
			)
		ORDER BY observed_unix_seconds, observed_nanosecond, event_id
		LIMIT ?
	`,
		endLimit.Unix(), endLimit.Unix(), endLimit.Nanosecond(),
		watermark.Unix(), watermark.Unix(), watermark.Nanosecond(),
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query batch observations: %w", err)
	}
	defer rows.Close()

	var observations []storedObservation
	for rows.Next() {
		var observation storedObservation
		var kind string
		var observedAt string
		var ruleIDsJSON string
		if err := rows.Scan(
			&observation.eventID,
			&kind,
			&observedAt,
			&observation.sourceIP,
			&observation.value,
			&ruleIDsJSON,
		); err != nil {
			return nil, fmt.Errorf("scan batch observation: %w", err)
		}
		observation.kind = protocol.ObservationKind(kind)
		observation.observedAt, err = time.Parse(time.RFC3339Nano, observedAt)
		if err != nil {
			return nil, fmt.Errorf("parse stored observation time: %w", err)
		}
		if err := json.Unmarshal([]byte(ruleIDsJSON), &observation.ruleIDs); err != nil {
			return nil, fmt.Errorf("decode stored rule IDs: %w", err)
		}
		observations = append(observations, observation)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate batch observations: %w", err)
	}
	return observations, nil
}

func buildPayload(
	config BatchConfig,
	sequence, previousHash string,
	createdAt time.Time,
	observations []storedObservation,
) protocol.BatchPayload {
	type aggregate struct {
		record  protocol.BatchRecord
		buckets map[time.Time]uint64
		first   time.Time
		last    time.Time
	}
	groups := make(map[string]*aggregate)
	first := observations[0].observedAt
	last := first

	for _, observation := range observations {
		if observation.observedAt.Before(first) {
			first = observation.observedAt
		}
		if observation.observedAt.After(last) {
			last = observation.observedAt
		}
		key := string(observation.kind) + "\x00" + observation.sourceIP + "\x00" +
			observation.value + "\x00" + strings.Join(observation.ruleIDs, "\x1f")
		group := groups[key]
		if group == nil {
			group = &aggregate{
				record: protocol.BatchRecord{
					Kind:            observation.kind,
					SourceIP:        observation.sourceIP,
					Count:           0,
					FirstObservedAt: observation.observedAt.Format(time.RFC3339Nano),
					LastObservedAt:  observation.observedAt.Format(time.RFC3339Nano),
				},
				buckets: make(map[time.Time]uint64),
				first:   observation.observedAt,
				last:    observation.observedAt,
			}
			if observation.kind == protocol.ObservationSSHAuthFailure {
				group.record.Username = observation.value
			} else {
				group.record.Path = observation.value
			}
			group.record.RuleIDs = append([]string(nil), observation.ruleIDs...)
			groups[key] = group
		}
		group.record.Count++
		if observation.observedAt.Before(group.first) {
			group.first = observation.observedAt
			group.record.FirstObservedAt = observation.observedAt.Format(time.RFC3339Nano)
		}
		if observation.observedAt.After(group.last) {
			group.last = observation.observedAt
			group.record.LastObservedAt = observation.observedAt.Format(time.RFC3339Nano)
		}
		group.buckets[observation.observedAt.Truncate(time.Hour)]++
	}

	records := make([]protocol.BatchRecord, 0, len(groups))
	for _, group := range groups {
		for hour, count := range group.buckets {
			group.record.HourlyBuckets = append(group.record.HourlyBuckets, protocol.HourlyBucket{
				Hour:  hour.Format(time.RFC3339Nano),
				Count: count,
			})
		}
		sort.Slice(group.record.HourlyBuckets, func(i, j int) bool {
			return group.record.HourlyBuckets[i].Hour < group.record.HourlyBuckets[j].Hour
		})
		records = append(records, group.record)
	}
	sort.Slice(records, func(i, j int) bool {
		return batchRecordSortKey(records[i]) < batchRecordSortKey(records[j])
	})

	return protocol.BatchPayload{
		SchemaVersion:     protocol.BatchSchemaVersion,
		SourceID:          config.SourceID,
		SourceEpoch:       config.SourceEpoch,
		Sequence:          sequence,
		PreviousBatchHash: previousHash,
		CreatedAt:         createdAt.Format(time.RFC3339Nano),
		ObservationWindow: protocol.TimeRange{
			Start: first.Truncate(time.Hour).Format(time.RFC3339Nano),
			End:   last.Truncate(time.Hour).Add(time.Hour).Format(time.RFC3339Nano),
		},
		ClassifierVersion: config.ClassifierVersion,
		Records:           records,
	}
}

func batchRecordSortKey(record protocol.BatchRecord) string {
	value := record.Username
	if record.Kind == protocol.ObservationHTTPRequest {
		value = record.Path
	}
	return string(record.Kind) + "\x00" + record.SourceIP + "\x00" + value + "\x00" +
		record.FirstObservedAt + "\x00" + strings.Join(record.RuleIDs, "\x1f")
}

func incrementSequence(sequence string) (string, error) {
	value, err := strconv.ParseUint(sequence, 10, 64)
	if err != nil {
		return "", errors.New("durable batch sequence is invalid")
	}
	if sequence == strings.Repeat("9", protocol.MaxSequenceDigits) {
		return "", errors.New("batch sequence is exhausted")
	}
	return strconv.FormatUint(value+1, 10), nil
}

func validGitObjectID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
