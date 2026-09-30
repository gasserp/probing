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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gasserp/probing/denylist"
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

// githubRepositoryPattern follows GitHub's owner and repository name rules
// closely enough to keep the value safe inside an API or raw-content URL path.
var githubRepositoryPattern = regexp.MustCompile(
	`^[A-Za-z0-9](?:[A-Za-z0-9]|-[A-Za-z0-9]){0,38}/[A-Za-z0-9._-]{1,100}$`,
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
	kind     string
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
	refreshSourceKinds(&ledger, registered)
	candidates, quarantine, err := loadCandidates(runContext, options.InputPath, registered, options.Now)
	if err != nil {
		return Result{}, err
	}
	result, err := acceptCandidates(runContext, &ledger, candidates, &quarantine)
	if err != nil {
		return Result{}, err
	}
	if err := prunePeriods(&ledger, options.Now); err != nil {
		return Result{}, err
	}
	denylist.Prune(ledger.DenyList, options.Now)
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
		switch source.Kind {
		case "":
			source.Kind = SourceKindHost
		case SourceKindDecoy, SourceKindHost:
		default:
			return Registry{}, nil, fmt.Errorf("registry source %d has an unknown kind", i)
		}
		if source.GitHubRepository != "" && !validGitHubRepository(source.GitHubRepository) {
			return Registry{}, nil, fmt.Errorf("registry source %d has an invalid github_repository", i)
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

func validGitHubRepository(value string) bool {
	if !githubRepositoryPattern.MatchString(value) {
		return false
	}
	name := value[strings.IndexByte(value, '/')+1:]
	return name != "." && name != ".." && !strings.HasSuffix(strings.ToLower(name), ".git")
}

// FetchTarget is an enabled source that publishes its batches to its own
// public GitHub repository. NextSequence is the lowest sequence acceptance
// still needs, so a fetcher can skip everything already in the ledger.
type FetchTarget struct {
	SourceID     string
	SourceEpoch  string
	Repository   string
	NextSequence string
}

// FetchTargets validates the registry and ledger exactly as Run does and
// returns the sources to pull from GitHub, sorted by source ID and epoch.
func FetchTargets(repositoryPath, repositoryIdentity string) ([]FetchTarget, error) {
	_, registered, err := loadRegistry(
		filepath.Join(repositoryPath, "registry", "sources.json"),
		repositoryIdentity,
	)
	if err != nil {
		return nil, err
	}
	ledger, err := loadLedger(
		filepath.Join(repositoryPath, "data", "acceptance-ledger.json"),
		repositoryIdentity,
	)
	if err != nil {
		return nil, err
	}
	targets := []FetchTarget{}
	for _, source := range registered {
		registration := source.registration
		if !registration.Enabled || registration.GitHubRepository == "" {
			continue
		}
		next := "0"
		if index, ok := ledgerSourceIndex(ledger, registration.SourceID, registration.SourceEpoch); ok {
			next = ledger.Sources[index].NextSequence
		}
		targets = append(targets, FetchTarget{
			SourceID:     registration.SourceID,
			SourceEpoch:  registration.SourceEpoch,
			Repository:   registration.GitHubRepository,
			NextSequence: next,
		})
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].SourceID != targets[j].SourceID {
			return targets[i].SourceID < targets[j].SourceID
		}
		return targets[i].SourceEpoch < targets[j].SourceEpoch
	})
	return targets, nil
}

// refreshSourceKinds copies each registered source's kind into the ledger so
// rollups label provenance with the registry's current classification, even
// for sources that submit no new batches in this run.
func refreshSourceKinds(ledger *Ledger, registered map[string]registeredSource) {
	for i := range ledger.Sources {
		source := &ledger.Sources[i]
		if registration, ok := registered[source.SourceID+"\x00"+source.SourceEpoch]; ok {
			source.Kind = registration.registration.Kind
		}
	}
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
			kind:     source.registration.Kind,
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
	for _, item := range candidates {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		payload := item.envelope.Batch.Payload
		index, exists := ledgerSourceIndex(*ledger, payload.SourceID, payload.SourceEpoch)
		if exists {
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
		}
		trial, reason, err := acceptNewCandidate(*ledger, item, MaxLedgerBytes)
		if err != nil {
			return Result{}, err
		}
		if reason != "" {
			addQuarantine(quarantine, item.relative, item.data, int64(len(item.data)), reason)
			continue
		}
		*ledger = trial
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

func acceptNewCandidate(ledger Ledger, item candidate, maxLedgerBytes int) (Ledger, string, error) {
	payload := item.envelope.Batch.Payload
	index, exists := ledgerSourceIndex(ledger, payload.SourceID, payload.SourceEpoch)
	nextSequence := "0"
	previousHash := ""
	if exists {
		nextSequence = ledger.Sources[index].NextSequence
		previousHash = ledger.Sources[index].PreviousHash
	}
	if payload.Sequence != nextSequence {
		return Ledger{}, "sequence_gap", nil
	}
	if payload.PreviousBatchHash != previousHash {
		return Ledger{}, "hash_chain_mismatch", nil
	}
	if totalAccepted(ledger) >= MaxAcceptedBatches {
		return Ledger{}, "", fmt.Errorf("acceptance ledger reached the %d-batch limit", MaxAcceptedBatches)
	}

	trial := cloneLedger(ledger)
	if !exists {
		trial.Sources = append(trial.Sources, LedgerSource{
			SourceID:     payload.SourceID,
			SourceEpoch:  payload.SourceEpoch,
			NextSequence: "0",
			Batches:      []LedgerBatch{},
		})
		index = len(trial.Sources) - 1
	}
	if err := applyPayload(&trial, payload, item.kind == SourceKindDecoy); err != nil {
		return Ledger{}, "", err
	}
	if err := applyDenyList(&trial, payload, item.kind); err != nil {
		return Ledger{}, "", err
	}
	source := &trial.Sources[index]
	source.Kind = item.kind
	source.Batches = append(source.Batches, LedgerBatch{
		Sequence:    payload.Sequence,
		PayloadHash: item.envelope.PayloadHash,
		BlobName:    item.envelope.BlobName,
	})
	source.PreviousHash = item.envelope.PayloadHash
	next, err := incrementSequence(payload.Sequence)
	if err != nil {
		return Ledger{}, "", err
	}
	source.NextSequence = next
	if newerTimestamp(payload.CreatedAt, trial.UpdatedAt) {
		trial.UpdatedAt = payload.CreatedAt
	}
	encoded, err := json.Marshal(trial)
	if err != nil {
		return Ledger{}, "", fmt.Errorf("encode acceptance ledger candidate: %w", err)
	}
	if len(encoded)+1 > maxLedgerBytes {
		return Ledger{}, "ledger_limit", nil
	}
	return trial, "", nil
}

func ledgerSourceIndex(ledger Ledger, sourceID, sourceEpoch string) (int, bool) {
	for i := range ledger.Sources {
		source := ledger.Sources[i]
		if source.SourceID == sourceID && source.SourceEpoch == sourceEpoch {
			return i, true
		}
	}
	return 0, false
}

func cloneLedger(ledger Ledger) Ledger {
	clone := Ledger{
		SchemaVersion: ledger.SchemaVersion,
		Repository:    ledger.Repository,
		UpdatedAt:     ledger.UpdatedAt,
		Sources:       make([]LedgerSource, len(ledger.Sources)),
		Periods:       make(map[string]PeriodLedger, len(ledger.Periods)),
		DenyList:      denylist.Clone(ledger.DenyList),
	}
	for i, source := range ledger.Sources {
		clone.Sources[i] = source
		clone.Sources[i].Batches = append([]LedgerBatch(nil), source.Batches...)
	}
	for key, period := range ledger.Periods {
		// Copy the whole struct first so scalar fields, including any added
		// later, carry over; then replace every map with its own copy.
		copied := period
		copied.Sources = cloneCounts(period.Sources)
		copied.SourceIPs = cloneCounts(period.SourceIPs)
		copied.Usernames = cloneCounts(period.Usernames)
		copied.Paths = cloneCounts(period.Paths)
		if period.Passwords != nil {
			copied.Passwords = cloneCounts(period.Passwords)
		}
		clone.Periods[key] = copied
	}
	return clone
}

func cloneCounts(values map[string]uint64) map[string]uint64 {
	clone := make(map[string]uint64, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}

func writeOutputs(root, ledgerPath string, ledger Ledger, quarantine Quarantine) error {
	ledgerBytes, err := jsonLine(ledger)
	if err != nil {
		return fmt.Errorf("encode acceptance ledger: %w", err)
	}
	if len(ledgerBytes) > MaxLedgerBytes {
		return fmt.Errorf("acceptance ledger exceeds the %d-byte limit", MaxLedgerBytes)
	}
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
	if err := publication.AtomicWrite(ledgerPath, ledgerBytes, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(ledgerPath), err)
	}
	return nil
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
	data, err := jsonLine(value)
	if err != nil {
		return fmt.Errorf("encode %s: %w", filepath.Base(path), err)
	}
	if err := publication.AtomicWrite(path, data, mode); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	return nil
}

func jsonLine(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
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
