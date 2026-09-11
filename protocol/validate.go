package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MaxBatchRecords         = 10_000
	MaxHourlyBuckets        = 744
	MaxRuleIDs              = 16
	MaxEncodedBatchBytes    = 1 << 20
	MaxEncodedEnvelopeBytes = MaxEncodedBatchBytes + 4_096
	MaxSafeJSONInteger      = uint64(1<<53 - 1)
	MaxObservationWindow    = 31 * 24 * time.Hour
	MaxSourceIDBytes        = 64
	MaxClassifierBytes      = 128
	MaxEventIDBytes         = 128
	MaxCursorBytes          = 1_024
	MaxUsernameBytes        = 256
	MaxPathBytes            = 2_048
	MaxRuleIDBytes          = 128
	MaxKeyIDBytes           = 128
	MaxSequenceDigits       = 19
)

var (
	sourceIDPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$`)
	epochPattern    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	hashPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	ruleIDPattern   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._/-]{0,126}[a-z0-9])?$`)
)

func ValidateObservation(observation Observation) error {
	if observation.SchemaVersion != ObservationSchemaVersion {
		return fmt.Errorf("unsupported observation schema version %q", observation.SchemaVersion)
	}
	if !validBoundedText(observation.EventID, MaxEventIDBytes) {
		return errors.New("event_id is invalid")
	}
	if !validBoundedText(observation.Cursor, MaxCursorBytes) {
		return errors.New("cursor is invalid")
	}
	if _, err := parseUTC(observation.ObservedAt); err != nil {
		return fmt.Errorf("observed_at: %w", err)
	}
	ip, err := netip.ParseAddr(observation.SourceIP)
	if err != nil || ip.IsUnspecified() {
		return errors.New("source_ip must be a specified IPv4 or IPv6 address")
	}
	if ip.Zone() != "" || observation.SourceIP != ip.Unmap().String() {
		return errors.New("source_ip must use canonical unmapped notation without a zone")
	}

	switch observation.Kind {
	case ObservationSSHAuthFailure:
		if observation.SSH == nil || observation.HTTP != nil {
			return errors.New("SSH observation requires only the ssh payload")
		}
		if !validBoundedText(observation.SSH.Username, MaxUsernameBytes) {
			return errors.New("SSH username is invalid")
		}
	case ObservationHTTPRequest:
		if observation.HTTP == nil || observation.SSH != nil {
			return errors.New("HTTP observation requires only the http payload")
		}
		if !validBoundedText(observation.HTTP.RequestTarget, MaxPathBytes) {
			return errors.New("HTTP request target is invalid")
		}
		if observation.HTTP.Status < 100 || observation.HTTP.Status > 599 {
			return errors.New("HTTP status is invalid")
		}
	default:
		return fmt.Errorf("unsupported observation kind %q", observation.Kind)
	}
	return nil
}

func ValidateBatchPayload(payload BatchPayload) error {
	if payload.SchemaVersion != BatchSchemaVersion {
		return fmt.Errorf("unsupported schema version %q", payload.SchemaVersion)
	}
	if err := ValidateSourceIdentity(payload.SourceID, payload.SourceEpoch); err != nil {
		return err
	}
	if err := validateSequence(payload.Sequence); err != nil {
		return err
	}
	if payload.Sequence == "0" {
		if payload.PreviousBatchHash != "" {
			return errors.New("sequence zero must not have a previous_batch_hash")
		}
	} else if !hashPattern.MatchString(payload.PreviousBatchHash) {
		return errors.New("nonzero sequence requires a lowercase SHA-256 previous_batch_hash")
	}
	if _, err := parseUTC(payload.CreatedAt); err != nil {
		return fmt.Errorf("created_at: %w", err)
	}
	windowStart, err := parseUTC(payload.ObservationWindow.Start)
	if err != nil {
		return fmt.Errorf("observation_window.start: %w", err)
	}
	windowEnd, err := parseUTC(payload.ObservationWindow.End)
	if err != nil {
		return fmt.Errorf("observation_window.end: %w", err)
	}
	if !windowStart.Before(windowEnd) {
		return errors.New("observation window must be a non-empty half-open interval")
	}
	if windowEnd.Sub(windowStart) > MaxObservationWindow {
		return fmt.Errorf("observation window must not exceed %s", MaxObservationWindow)
	}
	if payload.ClassifierVersion == "" || len(payload.ClassifierVersion) > MaxClassifierBytes {
		return errors.New("classifier_version is invalid")
	}
	if len(payload.Records) == 0 || len(payload.Records) > MaxBatchRecords {
		return fmt.Errorf("records must contain between 1 and %d entries", MaxBatchRecords)
	}

	var previousKey string
	for i, record := range payload.Records {
		if err := validateRecord(record, windowStart, windowEnd); err != nil {
			return fmt.Errorf("record %d: %w", i, err)
		}
		key := recordSortKey(record)
		if i > 0 && key <= previousKey {
			return errors.New("records must be uniquely sorted by kind, source_ip, value, and first_observed_at")
		}
		previousKey = key
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal batch for size validation: %w", err)
	}
	if len(encoded) > MaxEncodedBatchBytes {
		return fmt.Errorf("encoded batch payload exceeds %d bytes", MaxEncodedBatchBytes)
	}
	return nil
}

func ValidateSourceIdentity(sourceID, sourceEpoch string) error {
	if len(sourceID) > MaxSourceIDBytes || !sourceIDPattern.MatchString(sourceID) {
		return errors.New("source_id is invalid")
	}
	if !epochPattern.MatchString(sourceEpoch) {
		return errors.New("source_epoch must be a lowercase UUID")
	}
	return nil
}

func ValidateKeyID(keyID string) error {
	if !validBoundedText(keyID, MaxKeyIDBytes) {
		return errors.New("key ID is invalid")
	}
	return nil
}

func ValidateRuleIDs(ruleIDs []string) error {
	if len(ruleIDs) == 0 || len(ruleIDs) > MaxRuleIDs || !slices.IsSorted(ruleIDs) {
		return fmt.Errorf("rule_ids must contain between 1 and %d sorted entries", MaxRuleIDs)
	}
	for i, ruleID := range ruleIDs {
		if len(ruleID) > MaxRuleIDBytes || !ruleIDPattern.MatchString(ruleID) {
			return fmt.Errorf("rule_id %d is invalid", i)
		}
		if i > 0 && ruleIDs[i-1] == ruleID {
			return errors.New("rule_ids must be unique")
		}
	}
	return nil
}

func validateSequence(sequence string) error {
	if sequence == "" || len(sequence) > MaxSequenceDigits || (len(sequence) > 1 && sequence[0] == '0') {
		return errors.New("sequence must be a canonical unsigned decimal string")
	}
	if _, err := strconv.ParseUint(sequence, 10, 64); err != nil {
		return errors.New("sequence must be a canonical unsigned decimal string")
	}
	return nil
}

func validateRecord(record BatchRecord, windowStart, windowEnd time.Time) error {
	ip, err := netip.ParseAddr(record.SourceIP)
	if err != nil || ip.IsUnspecified() {
		return errors.New("source_ip must be a specified IPv4 or IPv6 address")
	}
	if ip.Zone() != "" || record.SourceIP != ip.Unmap().String() {
		return errors.New("source_ip must use canonical unmapped notation without a zone")
	}
	if record.Count == 0 || record.Count > MaxSafeJSONInteger {
		return fmt.Errorf("count must be between 1 and %d", MaxSafeJSONInteger)
	}

	switch record.Kind {
	case ObservationSSHAuthFailure:
		if record.Username == "" || record.Path != "" {
			return errors.New("SSH records require username and prohibit path")
		}
		if !validBoundedText(record.Username, MaxUsernameBytes) {
			return errors.New("username is invalid")
		}
	case ObservationHTTPRequest:
		if record.Path == "" || record.Username != "" {
			return errors.New("HTTP records require path and prohibit username")
		}
		if !validBoundedText(record.Path, MaxPathBytes) {
			return errors.New("path is invalid")
		}
	default:
		return fmt.Errorf("unsupported observation kind %q", record.Kind)
	}

	first, err := parseUTC(record.FirstObservedAt)
	if err != nil {
		return fmt.Errorf("first_observed_at: %w", err)
	}
	last, err := parseUTC(record.LastObservedAt)
	if err != nil {
		return fmt.Errorf("last_observed_at: %w", err)
	}
	if last.Before(first) {
		return errors.New("last_observed_at precedes first_observed_at")
	}
	if first.Before(windowStart) || !last.Before(windowEnd) {
		return errors.New("record timestamps fall outside the half-open observation window")
	}

	if len(record.HourlyBuckets) == 0 || len(record.HourlyBuckets) > MaxHourlyBuckets {
		return fmt.Errorf("hourly_buckets must contain between 1 and %d entries", MaxHourlyBuckets)
	}
	var bucketTotal uint64
	var previousHour time.Time
	for i, bucket := range record.HourlyBuckets {
		hour, err := parseUTC(bucket.Hour)
		if err != nil {
			return fmt.Errorf("hourly bucket %d: %w", i, err)
		}
		if !hour.Equal(hour.Truncate(time.Hour)) {
			return fmt.Errorf("hourly bucket %d is not aligned to an hour", i)
		}
		if hour.Before(windowStart.Truncate(time.Hour)) || !hour.Before(windowEnd) {
			return fmt.Errorf("hourly bucket %d falls outside the observation window", i)
		}
		if i > 0 && !previousHour.Before(hour) {
			return errors.New("hourly buckets must be uniquely sorted")
		}
		if bucket.Count == 0 || bucket.Count > MaxSafeJSONInteger {
			return fmt.Errorf("hourly bucket count must be between 1 and %d", MaxSafeJSONInteger)
		}
		if ^uint64(0)-bucketTotal < bucket.Count {
			return errors.New("hourly bucket count overflow")
		}
		bucketTotal += bucket.Count
		previousHour = hour
	}
	if bucketTotal != record.Count {
		return errors.New("hourly bucket counts do not equal record count")
	}
	firstBucketHour, _ := parseUTC(record.HourlyBuckets[0].Hour)
	if !firstBucketHour.Equal(first.Truncate(time.Hour)) {
		return errors.New("first hourly bucket does not match first_observed_at")
	}
	lastBucketHour, _ := parseUTC(record.HourlyBuckets[len(record.HourlyBuckets)-1].Hour)
	if !lastBucketHour.Equal(last.Truncate(time.Hour)) {
		return errors.New("last hourly bucket does not match last_observed_at")
	}

	if err := ValidateRuleIDs(record.RuleIDs); err != nil {
		return err
	}
	return nil
}

func parseUTC(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, errors.New("must be RFC 3339")
	}
	if parsed.Location() != time.UTC || !strings.HasSuffix(value, "Z") {
		return time.Time{}, errors.New("must use UTC with a Z suffix")
	}
	return parsed, nil
}

func validBoundedText(value string, maxBytes int) bool {
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

func recordSortKey(record BatchRecord) string {
	value := record.Username
	if record.Kind == ObservationHTTPRequest {
		value = record.Path
	}
	return string(record.Kind) + "\x00" + record.SourceIP + "\x00" + value + "\x00" +
		record.FirstObservedAt + "\x00" + strings.Join(record.RuleIDs, "\x1f")
}
