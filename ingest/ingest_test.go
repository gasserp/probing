package ingest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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

func writeRegistry(t *testing.T, repository string, publicKey ed25519.PublicKey) {
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
