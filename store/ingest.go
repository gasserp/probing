package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gasserp/probing/protocol"
)

const MaxAdapterIDBytes = 128

var ErrEventIDCollision = errors.New("event ID already exists with different content")

type ClassifiedObservation struct {
	Observation protocol.Observation
	Promoted    bool
	PublicPath  string
	RuleIDs     []string
}

type PromotionUpdate struct {
	EventID string
	RuleIDs []string
}

func (s *Store) HasSSHObservation(
	ctx context.Context,
	observation protocol.Observation,
) (bool, error) {
	if err := protocol.ValidateObservation(observation); err != nil {
		return false, err
	}
	if observation.Kind != protocol.ObservationSSHAuthFailure {
		return false, errors.New("stored replay lookup requires an SSH observation")
	}
	eventHash, err := observationHash(observation, "")
	if err != nil {
		return false, err
	}
	var existingHash string
	err = s.db.QueryRowContext(
		ctx,
		`SELECT event_hash FROM observations WHERE event_id = ?`,
		observation.EventID,
	).Scan(&existingHash)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read stored SSH observation: %w", err)
	}
	if existingHash != eventHash {
		return false, fmt.Errorf("%w: %s", ErrEventIDCollision, observation.EventID)
	}
	return true, nil
}

func (s *Store) CommitObservation(
	ctx context.Context,
	adapterID string,
	input ClassifiedObservation,
	promotions ...PromotionUpdate,
) (bool, error) {
	if !validText(adapterID, MaxAdapterIDBytes) {
		return false, errors.New("adapter ID is invalid")
	}
	if err := protocol.ValidateObservation(input.Observation); err != nil {
		return false, err
	}
	if err := validateClassification(input); err != nil {
		return false, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin observation transaction: %w", err)
	}
	defer tx.Rollback()

	inserted := false
	if input.Observation.Kind == protocol.ObservationSSHAuthFailure || input.Promoted {
		inserted, err = insertObservation(ctx, tx, adapterID, input)
		if err != nil {
			return false, err
		}
	}
	if err := applyPromotions(ctx, tx, promotions); err != nil {
		return false, err
	}
	if err := advanceCursor(ctx, tx, adapterID, input.Observation.Cursor); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit observation transaction: %w", err)
	}
	return inserted, nil
}

func (s *Store) CommitCursor(ctx context.Context, adapterID, cursor string) error {
	if !validText(adapterID, MaxAdapterIDBytes) {
		return errors.New("adapter ID is invalid")
	}
	if !validText(cursor, protocol.MaxCursorBytes) {
		return errors.New("adapter cursor is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin cursor transaction: %w", err)
	}
	defer tx.Rollback()
	if err := advanceCursor(ctx, tx, adapterID, cursor); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit cursor transaction: %w", err)
	}
	return nil
}

func advanceCursor(ctx context.Context, tx *sql.Tx, adapterID, cursor string) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO adapter_cursors (adapter_id, cursor, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(adapter_id) DO UPDATE SET
			cursor = excluded.cursor,
			updated_at = excluded.updated_at
	`, adapterID, cursor, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("advance adapter cursor: %w", err)
	}
	return nil
}

func insertObservation(
	ctx context.Context,
	tx *sql.Tx,
	adapterID string,
	input ClassifiedObservation,
) (bool, error) {
	observation := input.Observation
	eventHash, err := observationHash(observation, input.PublicPath)
	if err != nil {
		return false, err
	}

	var username any
	var path any
	var status any
	if observation.SSH != nil {
		username = observation.SSH.Username
	}
	if observation.HTTP != nil {
		path = input.PublicPath
		status = observation.HTTP.Status
	}
	ruleIDs, err := json.Marshal(input.RuleIDs)
	if err != nil {
		return false, fmt.Errorf("encode observation rules: %w", err)
	}
	observedAt, _ := time.Parse(time.RFC3339Nano, observation.ObservedAt)

	result, err := tx.ExecContext(ctx, `
		INSERT INTO observations (
			event_id, event_hash, adapter_id, cursor, kind, observed_at,
			observed_unix_seconds, observed_nanosecond, source_ip,
			username, path, http_status,
			promoted, rule_ids
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(event_id) DO NOTHING
	`,
		observation.EventID,
		eventHash,
		adapterID,
		observation.Cursor,
		string(observation.Kind),
		observation.ObservedAt,
		observedAt.Unix(),
		observedAt.Nanosecond(),
		observation.SourceIP,
		username,
		path,
		status,
		boolToInt(input.Promoted),
		string(ruleIDs),
	)
	if err != nil {
		return false, fmt.Errorf("insert observation: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("inspect observation insert: %w", err)
	}
	if rows == 1 {
		return true, nil
	}

	var existingHash string
	if err := tx.QueryRowContext(
		ctx,
		`SELECT event_hash FROM observations WHERE event_id = ?`,
		observation.EventID,
	).Scan(&existingHash); err != nil {
		return false, fmt.Errorf("read duplicate observation: %w", err)
	}
	if existingHash != eventHash {
		return false, fmt.Errorf("%w: %s", ErrEventIDCollision, observation.EventID)
	}
	return false, nil
}

func observationHash(observation protocol.Observation, publicPath string) (string, error) {
	hashObservation := observation
	hashObservation.Cursor = ""
	if hashObservation.HTTP != nil {
		hashObservation.HTTP = &protocol.HTTPObservation{
			RequestTarget: publicPath,
			Status:        hashObservation.HTTP.Status,
		}
	}
	encoded, err := json.Marshal(hashObservation)
	if err != nil {
		return "", fmt.Errorf("encode observation hash input: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func applyPromotions(ctx context.Context, tx *sql.Tx, updates []PromotionUpdate) error {
	if len(updates) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(updates))
	for _, update := range updates {
		if !validText(update.EventID, protocol.MaxEventIDBytes) {
			return errors.New("promotion event ID is invalid")
		}
		if _, duplicate := seen[update.EventID]; duplicate {
			return fmt.Errorf("duplicate promotion update for %q", update.EventID)
		}
		seen[update.EventID] = struct{}{}
		if err := protocol.ValidateRuleIDs(update.RuleIDs); err != nil {
			return fmt.Errorf("promotion %s: %w", update.EventID, err)
		}

		var kind string
		var existingJSON string
		var batchSequence sql.NullString
		if err := tx.QueryRowContext(ctx, `
			SELECT kind, rule_ids, batch_sequence
			FROM observations
			WHERE event_id = ?
		`, update.EventID).Scan(&kind, &existingJSON, &batchSequence); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("promotion references unknown event %q", update.EventID)
			}
			return fmt.Errorf("read promotion target: %w", err)
		}
		if protocol.ObservationKind(kind) != protocol.ObservationSSHAuthFailure {
			return fmt.Errorf("promotion event %q is not an SSH failure", update.EventID)
		}
		if batchSequence.Valid {
			return fmt.Errorf("promotion event %q is already in immutable batch %s", update.EventID, batchSequence.String)
		}

		var existing []string
		if err := json.Unmarshal([]byte(existingJSON), &existing); err != nil {
			return fmt.Errorf("decode existing promotion rules: %w", err)
		}
		merged := mergeSortedUnique(existing, update.RuleIDs)
		if err := protocol.ValidateRuleIDs(merged); err != nil {
			return fmt.Errorf("merged promotion %s: %w", update.EventID, err)
		}
		encoded, err := json.Marshal(merged)
		if err != nil {
			return fmt.Errorf("encode promotion rules: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE observations
			SET promoted = 1, rule_ids = ?
			WHERE event_id = ?
		`, string(encoded), update.EventID); err != nil {
			return fmt.Errorf("apply promotion: %w", err)
		}
	}
	return nil
}

func validateClassification(input ClassifiedObservation) error {
	if input.Promoted {
		if err := protocol.ValidateRuleIDs(input.RuleIDs); err != nil {
			return err
		}
	} else if len(input.RuleIDs) != 0 {
		return errors.New("unpromoted observation must not carry rule IDs")
	}

	switch input.Observation.Kind {
	case protocol.ObservationSSHAuthFailure:
		if input.PublicPath != "" || input.Promoted || len(input.RuleIDs) != 0 {
			return errors.New("SSH observation promotion must be supplied as atomic promotion updates")
		}
	case protocol.ObservationHTTPRequest:
		if !input.Promoted {
			if input.PublicPath != "" {
				return errors.New("unpromoted HTTP observation must not carry a public path")
			}
			return nil
		}
		if !validText(input.PublicPath, protocol.MaxPathBytes) ||
			!strings.HasPrefix(input.PublicPath, "/") ||
			strings.ContainsAny(input.PublicPath, "?#") {
			return errors.New("promoted HTTP observation requires a bounded query-free origin-form path")
		}
	default:
		return errors.New("unsupported observation kind")
	}
	return nil
}

func mergeSortedUnique(left, right []string) []string {
	values := make(map[string]struct{}, len(left)+len(right))
	for _, value := range left {
		values[value] = struct{}{}
	}
	for _, value := range right {
		values[value] = struct{}{}
	}
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	slices.Sort(result)
	return result
}

func validText(value string, maxBytes int) bool {
	if value == "" || len(value) > maxBytes || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
