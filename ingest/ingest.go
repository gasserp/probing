package ingest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gasserp/probing/protocol"
	"github.com/gasserp/probing/publication"
)

const (
	MaxRegistryBytes   = 256 << 10
	MaxLedgerBytes     = 64 << 20
	MaxInputFiles      = 256
	MaxInputBytes      = 64 << 20
	MaxRegistered      = 64
	MaxAcceptedBatches = 100_000
	MaxQuarantine      = 256
	MaxQuarantineFile  = 512
	MaxRuntime         = 2 * time.Minute
)

type Options struct {
	RepositoryPath     string
	InputPath          string
	RepositoryIdentity string
	AcceptedManifest   string
	Now                time.Time
}

type candidate struct {
	relative string
	data     []byte
	envelope publication.Envelope
	key      ed25519.PublicKey
	valid    bool
	reason   string
}

type registeredSource struct {
	registration SourceRegistration
	publicKey    ed25519.PublicKey
}

func Run(ctx context.Context, options Options) (Result, error) {
	if options.RepositoryPath == "" || options.InputPath == "" || options.RepositoryIdentity == "" {
		return Result{}, errors.New("repository path, input path, and repository identity are required")
	}
	if options.Now.IsZero() {
		options.Now = time.Now().UTC()
	}
	if options.Now.Location() != time.UTC {
		return Result{}, errors.New("ingestion time must be UTC")
	}
	runContext, cancel := context.WithTimeout(ctx, MaxRuntime)
	defer cancel()

	_, registered, err := loadRegistry(
		filepath.Join(options.RepositoryPath, "registry", "sources.json"),
		options.RepositoryIdentity,
	)
	if err != nil {
		return Result{}, err
	}
	ledgerPath := filepath.Join(options.RepositoryPath, "data", "acceptance-ledger.json")
	ledger, err := loadLedger(ledgerPath, options.RepositoryIdentity)
	if err != nil {
		return Result{}, err
	}
	candidates, quarantine, err := loadCandidates(runContext, options.InputPath, registered, options.Now)
	if err != nil {
		return Result{}, err
	}
	result, err := acceptCandidates(runContext, &ledger, candidates, &quarantine)
	if err != nil {
		return Result{}, err
	}
	if len(quarantine.Entries) > 0 {
		quarantine.UpdatedAt = options.Now.Format(time.RFC3339Nano)
	} else if ledger.UpdatedAt != "" {
		quarantine.UpdatedAt = ledger.UpdatedAt
	} else {
		quarantine.UpdatedAt = "1970-01-01T00:00:00Z"
	}
	result.Quarantined = len(quarantine.Entries)

	if err := writeOutputs(options.RepositoryPath, ledgerPath, ledger, quarantine); err != nil {
		return Result{}, err
	}
	if options.AcceptedManifest != "" {
		manifest := struct {
			SchemaVersion string   `json:"schema_version"`
			Blobs         []string `json:"blobs"`
		}{
			SchemaVersion: "probing.accepted-manifest/v1",
			Blobs:         result.DeleteBlobs,
		}
		if err := atomicJSON(options.AcceptedManifest, manifest, 0o600); err != nil {
			return Result{}, err
		}
	}
	return result, nil
}

func loadRegistry(path, expectedRepository string) (Registry, map[string]registeredSource, error) {
	var registry Registry
	if err := decodeStrictFile(path, MaxRegistryBytes, &registry); err != nil {
		return Registry{}, nil, fmt.Errorf("load source registry: %w", err)
	}
	if registry.SchemaVersion != RegistrySchemaVersion || registry.Repository != expectedRepository {
		return Registry{}, nil, errors.New("source registry schema or repository identity is invalid")
	}
	if len(registry.Sources) > MaxRegistered {
		return Registry{}, nil, fmt.Errorf("source registry must contain at most %d sources", MaxRegistered)
	}
	registered := make(map[string]registeredSource, len(registry.Sources))
	for i, source := range registry.Sources {
		if err := protocol.ValidateSourceIdentity(source.SourceID, source.SourceEpoch); err != nil {
			return Registry{}, nil, fmt.Errorf("registry source %d: %w", i, err)
		}
		if err := protocol.ValidateKeyID(source.KeyID); err != nil {
			return Registry{}, nil, fmt.Errorf("registry source %d: %w", i, err)
		}
		expectedPrefix := source.SourceID + "/" + source.SourceEpoch + "/"
		if source.BlobPrefix != expectedPrefix {
			return Registry{}, nil, fmt.Errorf("registry source %d has a non-deterministic blob_prefix", i)
		}
		keyBytes, err := base64.RawURLEncoding.DecodeString(source.PublicKey)
		if err != nil || len(keyBytes) != ed25519.PublicKeySize {
			return Registry{}, nil, fmt.Errorf("registry source %d has an invalid Ed25519 public key", i)
		}
		key := source.SourceID + "\x00" + source.SourceEpoch
		if _, duplicate := registered[key]; duplicate {
			return Registry{}, nil, errors.New("source registry contains a duplicate source epoch")
		}
		registered[key] = registeredSource{
			registration: source,
			publicKey:    ed25519.PublicKey(append([]byte(nil), keyBytes...)),
		}
	}
	return registry, registered, nil
}

func loadLedger(path, repository string) (Ledger, error) {
	ledger := Ledger{
		SchemaVersion: LedgerSchemaVersion,
		Repository:    repository,
		Sources:       []LedgerSource{},
		Periods:       make(map[string]PeriodLedger),
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return ledger, nil
	} else if err != nil {
		return Ledger{}, fmt.Errorf("inspect acceptance ledger: %w", err)
	}
	if err := decodeStrictFile(path, MaxLedgerBytes, &ledger); err != nil {
		return Ledger{}, fmt.Errorf("load acceptance ledger: %w", err)
	}
	if err := validateLedger(ledger, repository); err != nil {
		return Ledger{}, err
	}
	if ledger.Periods == nil {
		ledger.Periods = make(map[string]PeriodLedger)
	}
	return ledger, nil
}

func loadCandidates(
	ctx context.Context,
	root string,
	registered map[string]registeredSource,
	now time.Time,
) ([]candidate, Quarantine, error) {
	quarantine := Quarantine{
		SchemaVersion: QuarantineSchemaVersion,
		Entries:       []QuarantineEntry{},
	}
	var candidates []candidate
	var totalBytes int64
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("input tree must not contain symbolic links")
		}
		if !strings.HasSuffix(entry.Name(), ".json") {
			return nil
		}
		if len(candidates)+len(quarantine.Entries) >= MaxInputFiles {
			return fmt.Errorf("input contains more than %d JSON files", MaxInputFiles)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("input contains a non-regular JSON file")
		}
		totalBytes += info.Size()
		if totalBytes > MaxInputBytes {
			return fmt.Errorf("input exceeds the %d-byte limit", MaxInputBytes)
		}
		data, err := readFileBounded(path, protocol.MaxEncodedEnvelopeBytes)
		if err != nil {
			addQuarantine(&quarantine, relative, nil, info.Size(), "invalid_size")
			return nil
		}
		envelope, err := publication.ValidateEnvelope(data)
		if err != nil {
			addQuarantine(&quarantine, relative, data, info.Size(), "invalid_envelope")
			return nil
		}
		sourceKey := envelope.Batch.Payload.SourceID + "\x00" + envelope.Batch.Payload.SourceEpoch
		source, ok := registered[sourceKey]
		if !ok || !source.registration.Enabled {
			addQuarantine(&quarantine, relative, data, info.Size(), "unregistered_source")
			return nil
		}
		if source.registration.KeyID != envelope.Batch.Signature.KeyID {
			addQuarantine(&quarantine, relative, data, info.Size(), "unregistered_key")
			return nil
		}
		if !strings.HasPrefix(envelope.BlobName, source.registration.BlobPrefix) ||
			relative != envelope.BlobName {
			addQuarantine(&quarantine, relative, data, info.Size(), "invalid_blob_name")
			return nil
		}
		if err := protocol.VerifyBatch(envelope.Batch, source.publicKey); err != nil {
			addQuarantine(&quarantine, relative, data, info.Size(), "invalid_signature")
			return nil
		}
		if err := validateCentralTiming(envelope.Batch.Payload, now); err != nil {
			addQuarantine(&quarantine, relative, data, info.Size(), "invalid_time")
			return nil
		}
		candidates = append(candidates, candidate{
			relative: relative,
			data:     data,
			envelope: envelope,
			key:      source.publicKey,
			valid:    true,
		})
		return nil
	})
	if err != nil {
		return nil, Quarantine{}, fmt.Errorf("scan downloaded blobs: %w", err)
	}
	sort.Slice(candidates, func(i, j int) bool {
		left := candidates[i].envelope.Batch.Payload
		right := candidates[j].envelope.Batch.Payload
		if left.SourceID != right.SourceID {
			return left.SourceID < right.SourceID
		}
		if left.SourceEpoch != right.SourceEpoch {
			return left.SourceEpoch < right.SourceEpoch
		}
		leftSequence, _ := strconv.ParseUint(left.Sequence, 10, 64)
		rightSequence, _ := strconv.ParseUint(right.Sequence, 10, 64)
		if leftSequence != rightSequence {
			return leftSequence < rightSequence
		}
		return candidates[i].relative < candidates[j].relative
	})
	return candidates, quarantine, nil
}

func acceptCandidates(
	ctx context.Context,
	ledger *Ledger,
	candidates []candidate,
	quarantine *Quarantine,
) (Result, error) {
	result := Result{DeleteBlobs: []string{}}
	sourceIndexes := make(map[string]int, len(ledger.Sources))
	for i := range ledger.Sources {
		source := ledger.Sources[i]
		sourceIndexes[source.SourceID+"\x00"+source.SourceEpoch] = i
	}
	for _, item := range candidates {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		payload := item.envelope.Batch.Payload
		sourceKey := payload.SourceID + "\x00" + payload.SourceEpoch
		index, exists := sourceIndexes[sourceKey]
		if !exists {
			ledger.Sources = append(ledger.Sources, LedgerSource{
				SourceID:     payload.SourceID,
				SourceEpoch:  payload.SourceEpoch,
				NextSequence: "0",
				Batches:      []LedgerBatch{},
			})
			index = len(ledger.Sources) - 1
			sourceIndexes[sourceKey] = index
		}
		source := &ledger.Sources[index]
		if accepted, found := findAccepted(source.Batches, payload.Sequence); found {
			if accepted.PayloadHash != item.envelope.PayloadHash ||
				accepted.BlobName != item.envelope.BlobName {
				addQuarantine(quarantine, item.relative, item.data, int64(len(item.data)), "replay_conflict")
			} else {
				result.Replayed++
				result.DeleteBlobs = append(result.DeleteBlobs, item.envelope.BlobName)
			}
			continue
		}
		if payload.Sequence != source.NextSequence {
			addQuarantine(quarantine, item.relative, item.data, int64(len(item.data)), "sequence_gap")
			continue
		}
		if payload.PreviousBatchHash != source.PreviousHash {
			addQuarantine(quarantine, item.relative, item.data, int64(len(item.data)), "hash_chain_mismatch")
			continue
		}
		if totalAccepted(*ledger) >= MaxAcceptedBatches {
			return Result{}, fmt.Errorf("acceptance ledger reached the %d-batch limit", MaxAcceptedBatches)
		}
		if err := applyPayload(ledger, payload); err != nil {
			return Result{}, err
		}
		source.Batches = append(source.Batches, LedgerBatch{
			Sequence:    payload.Sequence,
			PayloadHash: item.envelope.PayloadHash,
			BlobName:    item.envelope.BlobName,
		})
		source.PreviousHash = item.envelope.PayloadHash
		next, err := incrementSequence(payload.Sequence)
		if err != nil {
			return Result{}, err
		}
		source.NextSequence = next
		if newerTimestamp(payload.CreatedAt, ledger.UpdatedAt) {
			ledger.UpdatedAt = payload.CreatedAt
		}
		result.Accepted++
		result.DeleteBlobs = append(result.DeleteBlobs, item.envelope.BlobName)
	}
	sort.Slice(ledger.Sources, func(i, j int) bool {
		if ledger.Sources[i].SourceID != ledger.Sources[j].SourceID {
			return ledger.Sources[i].SourceID < ledger.Sources[j].SourceID
		}
		return ledger.Sources[i].SourceEpoch < ledger.Sources[j].SourceEpoch
	})
	sort.Slice(quarantine.Entries, func(i, j int) bool {
		return quarantine.Entries[i].File < quarantine.Entries[j].File
	})
	sort.Strings(result.DeleteBlobs)
	return result, nil
}

func writeOutputs(root, ledgerPath string, ledger Ledger, quarantine Quarantine) error {
	dataDirectory := filepath.Join(root, "data")
	rollupDirectory := filepath.Join(dataDirectory, "rollups")
	if err := os.MkdirAll(rollupDirectory, 0o755); err != nil {
		return fmt.Errorf("create rollup directory: %w", err)
	}
	for _, granularity := range []string{"hourly", "daily", "monthly", "yearly"} {
		rollup, err := buildRollup(ledger, granularity)
		if err != nil {
			return err
		}
		if err := atomicJSON(
			filepath.Join(rollupDirectory, granularity+".json"),
			rollup,
			0o644,
		); err != nil {
			return err
		}
	}
	if err := atomicJSON(filepath.Join(dataDirectory, "quarantine.json"), quarantine, 0o644); err != nil {
		return err
	}
	return atomicJSON(ledgerPath, ledger, 0o644)
}

func decodeStrictFile(path string, limit int, output any) error {
	data, err := readFileBounded(path, limit)
	if err != nil {
		return err
	}
	if !utf8.Valid(data) {
		return errors.New("file is not valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("file contains trailing JSON")
	}
	return nil
}

func atomicJSON(path string, value any, mode os.FileMode) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode %s: %w", filepath.Base(path), err)
	}
	data = append(data, '\n')
	if err := publication.AtomicWrite(path, data, mode); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	return nil
}

func readFileBounded(path string, limit int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > limit {
		return nil, errors.New("file is empty or oversized")
	}
	return data, nil
}

func addQuarantine(quarantine *Quarantine, file string, data []byte, size int64, reason string) {
	if len(quarantine.Entries) >= MaxQuarantine {
		return
	}
	if !safeRelativeName(file) {
		file = "unsafe-name"
	}
	sum := sha256.Sum256(data)
	quarantine.Entries = append(quarantine.Entries, QuarantineEntry{
		File:   file,
		SHA256: hex.EncodeToString(sum[:]),
		Bytes:  size,
		Reason: reason,
	})
}

func safeRelativeName(value string) bool {
	if value == "" || len(value) > MaxQuarantineFile || !utf8.ValidString(value) ||
		strings.HasPrefix(value, "/") || strings.Contains(value, "..") {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func findAccepted(batches []LedgerBatch, sequence string) (LedgerBatch, bool) {
	for _, batch := range batches {
		if batch.Sequence == sequence {
			return batch, true
		}
	}
	return LedgerBatch{}, false
}

func totalAccepted(ledger Ledger) int {
	total := 0
	for _, source := range ledger.Sources {
		total += len(source.Batches)
	}
	return total
}

func incrementSequence(sequence string) (string, error) {
	value, err := strconv.ParseUint(sequence, 10, 64)
	if err != nil || sequence == strings.Repeat("9", protocol.MaxSequenceDigits) {
		return "", errors.New("batch sequence is exhausted")
	}
	return strconv.FormatUint(value+1, 10), nil
}

func validateCentralTiming(payload protocol.BatchPayload, now time.Time) error {
	createdAt, err := time.Parse(time.RFC3339Nano, payload.CreatedAt)
	if err != nil {
		return err
	}
	windowEnd, err := time.Parse(time.RFC3339Nano, payload.ObservationWindow.End)
	if err != nil {
		return err
	}
	if windowEnd.After(createdAt) {
		return errors.New("observation window ends after batch creation")
	}
	if createdAt.After(now.Add(5 * time.Minute)) {
		return errors.New("batch creation time exceeds allowed clock skew")
	}
	return nil
}

func newerTimestamp(candidate, current string) bool {
	if current == "" {
		return true
	}
	candidateTime, candidateErr := time.Parse(time.RFC3339Nano, candidate)
	currentTime, currentErr := time.Parse(time.RFC3339Nano, current)
	return candidateErr == nil && currentErr == nil && candidateTime.After(currentTime)
}
