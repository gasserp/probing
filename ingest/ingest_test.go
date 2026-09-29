package ingest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gasserp/probing/protocol"
	"github.com/gasserp/probing/publication"
)

func TestRunValidatesChainAndBuildsNonDuplicatedRollups(t *testing.T) {
	repository := t.TempDir()
	input := t.TempDir()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeRegistry(t, repository, publicKey)
	data := signedBatch(t, privateKey)
	envelope, err := publication.ValidateEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(input, filepath.FromSlash(envelope.BlobName))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(t.TempDir(), "accepted.json")
	result, err := Run(context.Background(), Options{
		RepositoryPath:     repository,
		InputPath:          input,
		RepositoryIdentity: "gasserp/probing-data",
		AcceptedManifest:   manifest,
		Now:                time.Date(2026, 9, 10, 21, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted != 1 || result.Quarantined != 0 || len(result.DeleteBlobs) != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}
	var rollup RollupFile
	readJSON(t, filepath.Join(repository, "data", "rollups", "hourly.json"), &rollup)
	if len(rollup.Periods) != 1 || rollup.Periods[0].Total != 2 {
		t.Fatalf("rule IDs duplicated observations in rollup: %#v", rollup)
	}
	if rollup.Periods[0].Sources[0].SourceID != "sensor-one" ||
		rollup.Periods[0].Sources[0].SourceEpoch != "5d6079de-20e0-4d4b-b955-40eac8f14df8" {
		t.Fatalf("source provenance missing: %#v", rollup.Periods[0].Sources)
	}

	result, err = Run(context.Background(), Options{
		RepositoryPath:     repository,
		InputPath:          input,
		RepositoryIdentity: "gasserp/probing-data",
		Now:                time.Date(2026, 9, 10, 22, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Replayed != 1 || result.Accepted != 0 {
		t.Fatalf("byte-identical replay was not idempotent: %#v", result)
	}
	readJSON(t, filepath.Join(repository, "data", "rollups", "hourly.json"), &rollup)
	if rollup.Periods[0].Total != 2 {
		t.Fatalf("replay changed total to %d", rollup.Periods[0].Total)
	}
}

func TestRunBootstrapsEmptyRepository(t *testing.T) {
	repository := t.TempDir()
	input := t.TempDir()
	registryPath := filepath.Join(repository, "registry", "sources.json")
	if err := os.MkdirAll(filepath.Dir(registryPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(registryPath, []byte(
		`{"schema_version":"probing.registry/v1","repository":"gasserp/probing-data","sources":[]}`,
	), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(t.TempDir(), "accepted.json")
	result, err := Run(context.Background(), Options{
		RepositoryPath:     repository,
		InputPath:          input,
		RepositoryIdentity: "gasserp/probing-data",
		AcceptedManifest:   manifest,
		Now:                time.Date(2026, 9, 11, 7, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted != 0 || result.Replayed != 0 || result.Quarantined != 0 {
		t.Fatalf("unexpected empty bootstrap result: %#v", result)
	}
	expected := map[string]string{
		filepath.Join(repository, "data", "acceptance-ledger.json"):  `{"schema_version":"probing.acceptance-ledger/v1","repository":"gasserp/probing-data","sources":[],"periods":{}}` + "\n",
		filepath.Join(repository, "data", "quarantine.json"):         `{"schema_version":"probing.quarantine/v1","updated_at":"1970-01-01T00:00:00Z","entries":[]}` + "\n",
		filepath.Join(repository, "data", "rollups", "hourly.json"):  `{"schema_version":"probing.rollup/v1","label":"self-reported suspected probes","granularity":"hourly","periods":[]}` + "\n",
		filepath.Join(repository, "data", "rollups", "daily.json"):   `{"schema_version":"probing.rollup/v1","label":"self-reported suspected probes","granularity":"daily","periods":[]}` + "\n",
		filepath.Join(repository, "data", "rollups", "monthly.json"): `{"schema_version":"probing.rollup/v1","label":"self-reported suspected probes","granularity":"monthly","periods":[]}` + "\n",
		filepath.Join(repository, "data", "rollups", "yearly.json"):  `{"schema_version":"probing.rollup/v1","label":"self-reported suspected probes","granularity":"yearly","periods":[]}` + "\n",
		manifest: `{"schema_version":"probing.accepted-manifest/v1","blobs":[]}` + "\n",
	}
	for path, want := range expected {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != want {
			t.Fatalf("%s = %q, want %q", path, data, want)
		}
	}
}

func TestRunQuarantinesUnregisteredSignatureWithoutCopyingContent(t *testing.T) {
	repository := t.TempDir()
	input := t.TempDir()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	_, wrongKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeRegistry(t, repository, publicKey)
	data := signedBatch(t, wrongKey)
	envelope, _ := publication.ValidateEnvelope(data)
	path := filepath.Join(input, filepath.FromSlash(envelope.BlobName))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Run(context.Background(), Options{
		RepositoryPath:     repository,
		InputPath:          input,
		RepositoryIdentity: "gasserp/probing-data",
		Now:                time.Date(2026, 9, 10, 21, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Quarantined != 1 || result.Accepted != 0 {
		t.Fatalf("unexpected result: %#v", result)
	}
	var quarantine Quarantine
	readJSON(t, filepath.Join(repository, "data", "quarantine.json"), &quarantine)
	if len(quarantine.Entries) != 1 || quarantine.Entries[0].Reason != "invalid_signature" {
		t.Fatalf("unexpected quarantine metadata: %#v", quarantine)
	}
}

func TestAcceptanceLimitsDoNotPoisonLedger(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data := signedBatch(t, privateKey)
	envelope, err := publication.ValidateEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	item := candidate{
		relative: envelope.BlobName,
		data:     data,
		envelope: envelope,
	}
	fullIPs := make(map[string]uint64, MaxPeriodDimensionValues)
	for i := range MaxPeriodDimensionValues {
		fullIPs[fmt.Sprintf("2001:db8::%x", i+0x10000)] = 1
	}
	ledger := Ledger{
		SchemaVersion: LedgerSchemaVersion,
		Repository:    "gasserp/probing-data",
		Sources:       []LedgerSource{},
		Periods: map[string]PeriodLedger{
			"hourly\x002026-09-10T19:00:00Z": {
				Total:     uint64(MaxPeriodDimensionValues),
				Sources:   map[string]uint64{},
				SourceIPs: fullIPs,
				Usernames: map[string]uint64{},
				Paths:     map[string]uint64{},
			},
		},
	}
	quarantine := Quarantine{SchemaVersion: QuarantineSchemaVersion, Entries: []QuarantineEntry{}}
	result, err := acceptCandidates(context.Background(), &ledger, []candidate{item}, &quarantine)
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted != 1 || len(quarantine.Entries) != 0 {
		t.Fatalf("cardinality exhaustion should overflow, not quarantine: result = %#v, quarantine = %#v", result, quarantine)
	}
	period := ledger.Periods["hourly\x002026-09-10T19:00:00Z"]
	if len(period.SourceIPs) != MaxPeriodDimensionValues {
		t.Fatalf("SourceIPs map should stay capped at %d entries, got %d", MaxPeriodDimensionValues, len(period.SourceIPs))
	}
	if period.SourceIPsOverflow != 2 {
		t.Fatalf("SourceIPsOverflow = %d, want 2", period.SourceIPsOverflow)
	}
	if period.Total != uint64(MaxPeriodDimensionValues)+2 {
		t.Fatalf("period.Total = %d, want %d", period.Total, uint64(MaxPeriodDimensionValues)+2)
	}
	root := t.TempDir()
	ledgerPath := filepath.Join(root, "data", "acceptance-ledger.json")
	if err := writeOutputs(root, ledgerPath, ledger, quarantine); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > MaxLedgerBytes {
		t.Fatalf("written ledger size = %d, limit = %d", info.Size(), MaxLedgerBytes)
	}
	if _, err := loadLedger(ledgerPath, "gasserp/probing-data"); err != nil {
		t.Fatalf("written ledger cannot be loaded: %v", err)
	}

	empty := Ledger{
		SchemaVersion: LedgerSchemaVersion,
		Repository:    "gasserp/probing-data",
		Sources:       []LedgerSource{},
		Periods:       map[string]PeriodLedger{},
	}
	if _, reason, err := acceptNewCandidate(empty, item, 1); err != nil || reason != "ledger_limit" {
		t.Fatalf("serialized ledger exhaustion = reason %q, error %v", reason, err)
	}
	if len(empty.Sources) != 0 || len(empty.Periods) != 0 {
		t.Fatal("serialized ledger exhaustion mutated the original ledger")
	}
}

func TestPrunePeriodsDropsOldHourlyAndTrimsOthers(t *testing.T) {
	ledger := Ledger{
		SchemaVersion: LedgerSchemaVersion,
		Periods: map[string]PeriodLedger{
			"hourly\x002026-01-01T00:00:00Z": {
				Total:     5,
				Sources:   map[string]uint64{},
				SourceIPs: map[string]uint64{},
				Usernames: map[string]uint64{},
				Paths:     map[string]uint64{},
			},
			"daily\x002026-01-01": {
				Total:     105,
				Sources:   make(map[string]uint64, 105),
				SourceIPs: map[string]uint64{},
				Usernames: map[string]uint64{},
				Paths:     map[string]uint64{},
			},
			"hourly\x002026-09-15T00:00:00Z": {
				Total:     105,
				Sources:   make(map[string]uint64, 105),
				SourceIPs: map[string]uint64{},
				Usernames: map[string]uint64{},
				Paths:     map[string]uint64{},
			},
		},
	}
	for i := 0; i < 105; i++ {
		ledger.Periods["daily\x002026-01-01"].Sources[fmt.Sprintf("source-%d", i)] = 1
		ledger.Periods["hourly\x002026-09-15T00:00:00Z"].Sources[fmt.Sprintf("source-%d", i)] = 1
	}

	now := time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC)
	if err := prunePeriods(&ledger, now); err != nil {
		t.Fatal(err)
	}

	// Old hourly period should be dropped
	if _, exists := ledger.Periods["hourly\x002026-01-01T00:00:00Z"]; exists {
		t.Fatal("old hourly period should have been dropped")
	}

	// Old daily period should be trimmed
	dailyPeriod := ledger.Periods["daily\x002026-01-01"]
	if len(dailyPeriod.Sources) != MaxPublicDimensionValues {
		t.Fatalf("daily period sources should be trimmed to %d entries, got %d", MaxPublicDimensionValues, len(dailyPeriod.Sources))
	}
	if dailyPeriod.SourcesOverflow != 5 {
		t.Fatalf("daily period sources overflow = %d, want 5", dailyPeriod.SourcesOverflow)
	}

	// Recent hourly period should be untouched
	hourlyPeriod := ledger.Periods["hourly\x002026-09-15T00:00:00Z"]
	if len(hourlyPeriod.Sources) != 105 {
		t.Fatalf("recent hourly period sources should remain at 105 entries, got %d", len(hourlyPeriod.Sources))
	}
	if hourlyPeriod.SourcesOverflow != 0 {
		t.Fatalf("recent hourly period sources overflow = %d, want 0", hourlyPeriod.SourcesOverflow)
	}
}

func TestApplyPayloadAccumulatesPasswords(t *testing.T) {
	ledger := Ledger{
		SchemaVersion: LedgerSchemaVersion,
		Repository:    "gasserp/probing-data",
		Sources:       []LedgerSource{},
		Periods:       map[string]PeriodLedger{},
	}
	payload := protocol.BatchPayload{
		SchemaVersion:     protocol.BatchSchemaVersion,
		SourceID:          "sensor-one",
		SourceEpoch:       "5d6079de-20e0-4d4b-b955-40eac8f14df8",
		Sequence:          "0",
		CreatedAt:         "2026-09-10T20:00:00Z",
		ObservationWindow: protocol.TimeRange{Start: "2026-09-10T19:00:00Z", End: "2026-09-10T20:00:00Z"},
		ClassifierVersion: "classifier-v1",
		Records: []protocol.BatchRecord{
			{
				Kind:            protocol.ObservationSSHAuthFailure,
				SourceIP:        "2001:db8::1",
				Username:        "root",
				Password:        "123456",
				Count:           3,
				FirstObservedAt: "2026-09-10T19:01:00Z",
				LastObservedAt:  "2026-09-10T19:02:00Z",
				HourlyBuckets:   []protocol.HourlyBucket{{Hour: "2026-09-10T19:00:00Z", Count: 3}},
				RuleIDs:         []string{"ssh/all-attempts-v1"},
			},
			{
				Kind:            protocol.ObservationSSHAuthFailure,
				SourceIP:        "2001:db8::1",
				Username:        "root",
				Count:           1,
				FirstObservedAt: "2026-09-10T19:03:00Z",
				LastObservedAt:  "2026-09-10T19:03:00Z",
				HourlyBuckets:   []protocol.HourlyBucket{{Hour: "2026-09-10T19:00:00Z", Count: 1}},
				RuleIDs:         []string{"ssh/all-attempts-v1"},
			},
		},
	}
	hostLedger := cloneLedger(ledger)
	if err := applyPayload(&hostLedger, payload, false); err != nil {
		t.Fatal(err)
	}
	hostPeriod := hostLedger.Periods["hourly\x002026-09-10T19:00:00Z"]
	if hostPeriod.Usernames["root"] != 4 || len(hostPeriod.Passwords) != 0 {
		t.Fatalf("non-decoy source must keep usernames but publish no passwords: %#v", hostPeriod)
	}

	if err := applyPayload(&ledger, payload, true); err != nil {
		t.Fatal(err)
	}
	period := ledger.Periods["hourly\x002026-09-10T19:00:00Z"]
	if got := period.Usernames["root"]; got != 4 {
		t.Fatalf("username count = %d, want 4", got)
	}
	if got := period.Passwords["123456"]; got != 3 {
		t.Fatalf("password count = %d, want 3", got)
	}
	if len(period.Passwords) != 1 {
		t.Fatalf("only the captured password should be tracked, got %d entries", len(period.Passwords))
	}

	rollup, err := buildRollup(ledger, "hourly")
	if err != nil {
		t.Fatal(err)
	}
	if len(rollup.Periods) != 1 {
		t.Fatalf("unexpected rollup periods: %#v", rollup.Periods)
	}
	passwords := rollup.Periods[0].Passwords
	if len(passwords) != 1 || passwords[0].Value != "123456" || passwords[0].Count != 3 {
		t.Fatalf("rollup passwords = %#v", passwords)
	}
}

func TestRunLabelsSourceKindFromRegistry(t *testing.T) {
	repository := t.TempDir()
	input := t.TempDir()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeRegistry(t, repository, publicKey)
	data := signedBatch(t, privateKey)
	envelope, err := publication.ValidateEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(input, filepath.FromSlash(envelope.BlobName))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	run := func() {
		t.Helper()
		if _, err := Run(context.Background(), Options{
			RepositoryPath:     repository,
			InputPath:          input,
			RepositoryIdentity: "gasserp/probing-data",
			Now:                time.Date(2026, 9, 10, 21, 0, 0, 0, time.UTC),
		}); err != nil {
			t.Fatal(err)
		}
	}
	sourceKind := func() string {
		t.Helper()
		var rollup RollupFile
		readJSON(t, filepath.Join(repository, "data", "rollups", "daily.json"), &rollup)
		if len(rollup.Periods) != 1 || len(rollup.Periods[0].Sources) != 1 {
			t.Fatalf("unexpected rollup: %#v", rollup)
		}
		return rollup.Periods[0].Sources[0].Kind
	}

	run()
	if kind := sourceKind(); kind != SourceKindHost {
		t.Fatalf("registration without kind labelled %q, want host", kind)
	}
	writeRegistryKind(t, repository, publicKey, SourceKindDecoy)
	run()
	if kind := sourceKind(); kind != SourceKindDecoy {
		t.Fatalf("reclassified source labelled %q, want decoy", kind)
	}

	writeRegistryKind(t, repository, publicKey, "honeypot")
	if _, err := Run(context.Background(), Options{
		RepositoryPath:     repository,
		InputPath:          input,
		RepositoryIdentity: "gasserp/probing-data",
		Now:                time.Date(2026, 9, 10, 21, 0, 0, 0, time.UTC),
	}); err == nil {
		t.Fatal("unknown source kind was accepted")
	}
}

func writeRegistry(t *testing.T, repository string, publicKey ed25519.PublicKey) {
	t.Helper()
	writeRegistryKind(t, repository, publicKey, "")
}

func writeRegistryKind(t *testing.T, repository string, publicKey ed25519.PublicKey, kind string) {
	t.Helper()
	path := filepath.Join(repository, "registry", "sources.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	registry := Registry{
		SchemaVersion: RegistrySchemaVersion,
		Repository:    "gasserp/probing-data",
		Sources: []SourceRegistration{{
			SourceID:    "sensor-one",
			SourceEpoch: "5d6079de-20e0-4d4b-b955-40eac8f14df8",
			KeyID:       "key-1",
			PublicKey:   base64.RawURLEncoding.EncodeToString(publicKey),
			BlobPrefix:  "sensor-one/5d6079de-20e0-4d4b-b955-40eac8f14df8/",
			Kind:        kind,
			Enabled:     true,
		}},
	}
	data, err := json.Marshal(registry)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func signedBatch(t *testing.T, privateKey ed25519.PrivateKey) []byte {
	t.Helper()
	payload := protocol.BatchPayload{
		SchemaVersion:     protocol.BatchSchemaVersion,
		SourceID:          "sensor-one",
		SourceEpoch:       "5d6079de-20e0-4d4b-b955-40eac8f14df8",
		Sequence:          "0",
		CreatedAt:         "2026-09-10T20:00:00Z",
		ObservationWindow: protocol.TimeRange{Start: "2026-09-10T19:00:00Z", End: "2026-09-10T20:00:00Z"},
		ClassifierVersion: "classifier-v1",
		Records: []protocol.BatchRecord{{
			Kind:            protocol.ObservationSSHAuthFailure,
			SourceIP:        "2001:db8::1",
			Username:        "root",
			Count:           2,
			FirstObservedAt: "2026-09-10T19:01:00Z",
			LastObservedAt:  "2026-09-10T19:02:00Z",
			HourlyBuckets:   []protocol.HourlyBucket{{Hour: "2026-09-10T19:00:00Z", Count: 2}},
			RuleIDs:         []string{"ssh/distinct-usernames-v1", "ssh/pair-threshold-v1"},
		}},
	}
	batch, err := protocol.SignBatch(payload, "key-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func readJSON(t *testing.T, path string, output any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, output); err != nil {
		t.Fatal(err)
	}
}

func TestFetchTargetsListsEnabledGitHubSourcesFromLedgerHead(t *testing.T) {
	repository := t.TempDir()
	input := t.TempDir()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeRegistrySource(t, repository, publicKey, func(source *SourceRegistration) {
		source.GitHubRepository = "alice/probing-batches"
	})
	targets, err := FetchTargets(repository, "gasserp/probing-data")
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].Repository != "alice/probing-batches" ||
		targets[0].SourceID != "sensor-one" || targets[0].NextSequence != "0" {
		t.Fatalf("unexpected targets before acceptance: %#v", targets)
	}

	data := signedBatch(t, privateKey)
	envelope, err := publication.ValidateEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(input, filepath.FromSlash(envelope.BlobName))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), Options{
		RepositoryPath:     repository,
		InputPath:          input,
		RepositoryIdentity: "gasserp/probing-data",
		Now:                time.Date(2026, 9, 10, 21, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}
	targets, err = FetchTargets(repository, "gasserp/probing-data")
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].NextSequence != "1" {
		t.Fatalf("fetch target does not resume after the accepted batch: %#v", targets)
	}

	writeRegistrySource(t, repository, publicKey, func(source *SourceRegistration) {
		source.GitHubRepository = "alice/probing-batches"
		source.Enabled = false
	})
	if targets, err := FetchTargets(repository, "gasserp/probing-data"); err != nil || len(targets) != 0 {
		t.Fatalf("disabled source is still fetched: %#v, %v", targets, err)
	}
	writeRegistry(t, repository, publicKey)
	if targets, err := FetchTargets(repository, "gasserp/probing-data"); err != nil || len(targets) != 0 {
		t.Fatalf("Blob-container source is fetched from GitHub: %#v, %v", targets, err)
	}
}

func TestRegistryRejectsInvalidGitHubRepository(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{
		"alice",
		"alice/",
		"/repo",
		"alice/repo/extra",
		"-alice/repo",
		"alice--x/repo",
		"alice/..",
		"alice/repo.git",
		"alice/re po",
		"alice/repo?x=1",
		"https://github.com/alice/repo",
	} {
		repository := t.TempDir()
		writeRegistrySource(t, repository, publicKey, func(source *SourceRegistration) {
			source.GitHubRepository = value
		})
		if _, err := FetchTargets(repository, "gasserp/probing-data"); err == nil {
			t.Errorf("github_repository %q was accepted", value)
		}
	}
}

func writeRegistrySource(
	t *testing.T,
	repository string,
	publicKey ed25519.PublicKey,
	edit func(*SourceRegistration),
) {
	t.Helper()
	writeRegistry(t, repository, publicKey)
	path := filepath.Join(repository, "registry", "sources.json")
	var registry Registry
	readJSON(t, path, &registry)
	edit(&registry.Sources[0])
	data, err := json.Marshal(registry)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestRunKeepsPasswordsAcrossAcceptances guards against cloneLedger dropping
// the password dimension: every acceptance works on a copy of the ledger, so
// a lost field silently erased all earlier passwords, and a host batch
// accepted after a decoy batch left none at all.
func TestRunKeepsPasswordsAcrossAcceptances(t *testing.T) {
	repository := t.TempDir()
	decoyPublic, decoyPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostPublic, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const decoyEpoch = "5d6079de-20e0-4d4b-b955-40eac8f14df8"
	const hostEpoch = "6e7180ef-31f1-4e5c-8a66-51fbf9025e09"
	registry := Registry{
		SchemaVersion: RegistrySchemaVersion,
		Repository:    "gasserp/probing-data",
		Sources: []SourceRegistration{
			{
				SourceID: "a-decoy", SourceEpoch: decoyEpoch, KeyID: "a-decoy-1",
				PublicKey:  base64.RawURLEncoding.EncodeToString(decoyPublic),
				BlobPrefix: "a-decoy/" + decoyEpoch + "/", Kind: SourceKindDecoy, Enabled: true,
			},
			{
				SourceID: "b-host", SourceEpoch: hostEpoch, KeyID: "b-host-1",
				PublicKey:  base64.RawURLEncoding.EncodeToString(hostPublic),
				BlobPrefix: "b-host/" + hostEpoch + "/", Kind: SourceKindHost, Enabled: true,
			},
		},
	}
	registryData, err := json.Marshal(registry)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repository, "registry"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "registry", "sources.json"), registryData, 0o600); err != nil {
		t.Fatal(err)
	}

	type batchSpec struct {
		sourceID, epoch, keyID, sequence, previous, hour, password string
		key                                                        ed25519.PrivateKey
	}
	write := func(input string, spec batchSpec) string {
		t.Helper()
		start, err := time.Parse(time.RFC3339, spec.hour)
		if err != nil {
			t.Fatal(err)
		}
		end := start.Add(time.Hour).Format(time.RFC3339)
		batch, err := protocol.SignBatch(protocol.BatchPayload{
			SchemaVersion:     protocol.BatchSchemaVersion,
			SourceID:          spec.sourceID,
			SourceEpoch:       spec.epoch,
			Sequence:          spec.sequence,
			PreviousBatchHash: spec.previous,
			CreatedAt:         end,
			ObservationWindow: protocol.TimeRange{Start: spec.hour, End: end},
			ClassifierVersion: "probing-classifier-v2",
			Records: []protocol.BatchRecord{{
				Kind:            protocol.ObservationSSHAuthFailure,
				SourceIP:        "2001:db8::1",
				Username:        "root",
				Password:        spec.password,
				Count:           1,
				FirstObservedAt: spec.hour,
				LastObservedAt:  spec.hour,
				HourlyBuckets:   []protocol.HourlyBucket{{Hour: spec.hour, Count: 1}},
				RuleIDs:         []string{"ssh/all-attempts-v1"},
			}},
		}, spec.keyID, spec.key)
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(batch)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := publication.ValidateEnvelope(data)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(input, filepath.FromSlash(envelope.BlobName))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return envelope.PayloadHash
	}
	run := func(input string) {
		t.Helper()
		result, err := Run(context.Background(), Options{
			RepositoryPath:     repository,
			InputPath:          input,
			RepositoryIdentity: "gasserp/probing-data",
			Now:                time.Date(2026, 9, 10, 23, 0, 0, 0, time.UTC),
		})
		if err != nil {
			t.Fatal(err)
		}
		if result.Quarantined != 0 {
			t.Fatalf("unexpected quarantine: %#v", result)
		}
	}
	passwords := func(granularity string) map[string]uint64 {
		t.Helper()
		var rollup RollupFile
		readJSON(t, filepath.Join(repository, "data", "rollups", granularity+".json"), &rollup)
		counts := map[string]uint64{}
		for _, period := range rollup.Periods {
			for _, value := range period.Passwords {
				counts[value.Value] += value.Count
			}
		}
		return counts
	}

	// One run: a decoy batch, then a host batch for the same hour.
	first := t.TempDir()
	decoyHash := write(first, batchSpec{
		sourceID: "a-decoy", epoch: decoyEpoch, keyID: "a-decoy-1", sequence: "0",
		hour: "2026-09-10T19:00:00Z", password: "123456", key: decoyPrivate,
	})
	write(first, batchSpec{
		sourceID: "b-host", epoch: hostEpoch, keyID: "b-host-1", sequence: "0",
		hour: "2026-09-10T19:00:00Z", password: "real-secret", key: hostPrivate,
	})
	run(first)
	for _, granularity := range []string{"hourly", "daily", "monthly", "yearly"} {
		got := passwords(granularity)
		if got["123456"] != 1 || got["real-secret"] != 0 || len(got) != 1 {
			t.Fatalf("%s passwords after decoy+host run = %v, want only 123456", granularity, got)
		}
	}

	// A later run with another decoy batch adds to, not replaces, earlier ones.
	second := t.TempDir()
	write(second, batchSpec{
		sourceID: "a-decoy", epoch: decoyEpoch, keyID: "a-decoy-1", sequence: "1", previous: decoyHash,
		hour: "2026-09-10T20:00:00Z", password: "admin", key: decoyPrivate,
	})
	run(second)
	if got := passwords("daily"); got["123456"] != 1 || got["admin"] != 1 {
		t.Fatalf("daily passwords after second run = %v, want 123456 and admin", got)
	}
	if got := passwords("hourly"); got["123456"] != 1 || got["admin"] != 1 {
		t.Fatalf("hourly passwords after second run = %v, want both hours kept", got)
	}
}
