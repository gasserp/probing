package fetch

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

	"github.com/gasserp/probing/ingest"
	"github.com/gasserp/probing/protocol"
	"github.com/gasserp/probing/publication"
)

// TestFetchedBatchesPassAcceptance runs the contributor path end to end:
// batches committed under their blob names are fetched, accepted in chain
// order, and not fetched again once the ledger has them.
func TestFetchedBatchesPassAcceptance(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	repository := t.TempDir()
	registry := ingest.Registry{
		SchemaVersion: ingest.RegistrySchemaVersion,
		Repository:    "gasserp/probing-data",
		Sources: []ingest.SourceRegistration{{
			SourceID:         "alice-pi",
			SourceEpoch:      testEpoch,
			KeyID:            "alice-pi-ed25519-1",
			PublicKey:        base64.RawURLEncoding.EncodeToString(publicKey),
			BlobPrefix:       "alice-pi/" + testEpoch + "/",
			Kind:             ingest.SourceKindHost,
			GitHubRepository: "alice/batches",
			Enabled:          true,
		}},
	}
	registryData, err := json.Marshal(registry)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repository, "registry"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "registry", "sources.json"), registryData, 0o644); err != nil {
		t.Fatal(err)
	}

	var files []fakeFile
	previous := ""
	for sequence, hour := range []string{"2026-09-10T18:00:00Z", "2026-09-10T19:00:00Z"} {
		start, _ := time.Parse(time.RFC3339, hour)
		end := start.Add(time.Hour).Format(time.RFC3339)
		batch, err := protocol.SignBatch(protocol.BatchPayload{
			SchemaVersion:     protocol.BatchSchemaVersion,
			SourceID:          "alice-pi",
			SourceEpoch:       testEpoch,
			Sequence:          []string{"0", "1"}[sequence],
			PreviousBatchHash: previous,
			CreatedAt:         end,
			ObservationWindow: protocol.TimeRange{Start: hour, End: end},
			ClassifierVersion: "probing-classifier-v2",
			Records: []protocol.BatchRecord{{
				Kind:            protocol.ObservationSSHAuthFailure,
				SourceIP:        "2001:db8::1",
				Username:        "root",
				Count:           1,
				FirstObservedAt: hour,
				LastObservedAt:  hour,
				HourlyBuckets:   []protocol.HourlyBucket{{Hour: hour, Count: 1}},
				RuleIDs:         []string{"ssh/all-attempts-v1"},
			}},
		}, "alice-pi-ed25519-1", privateKey)
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
		files = append(files, fakeFile{path: envelope.BlobName, data: data})
		previous = envelope.PayloadHash
	}
	fake := &fakeGitHub{t: t, repos: map[string][]fakeFile{"alice/batches": files}}
	server := fake.server()
	defer server.Close()

	run := func() (Report, ingest.Result) {
		t.Helper()
		targets, err := ingest.FetchTargets(repository, "gasserp/probing-data")
		if err != nil {
			t.Fatal(err)
		}
		input := t.TempDir()
		report, err := Run(context.Background(), options(server, input, targets...))
		if err != nil {
			t.Fatal(err)
		}
		result, err := ingest.Run(context.Background(), ingest.Options{
			RepositoryPath:     repository,
			InputPath:          input,
			RepositoryIdentity: "gasserp/probing-data",
			Now:                time.Date(2026, 9, 10, 21, 0, 0, 0, time.UTC),
		})
		if err != nil {
			t.Fatal(err)
		}
		return report, result
	}
	report, result := run()
	if report.Fetched != 2 || result.Accepted != 2 || result.Quarantined != 0 {
		t.Fatalf("first run: fetched %d, result %#v", report.Fetched, result)
	}
	report, result = run()
	if report.Fetched != 0 || result.Accepted != 0 {
		t.Fatalf("accepted batches were fetched again: fetched %d, result %#v", report.Fetched, result)
	}
}
