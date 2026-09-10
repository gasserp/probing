package core

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/gasserp/probing/classifier"
	"github.com/gasserp/probing/protocol"
	"github.com/gasserp/probing/store"
)

func TestProcessorRestoresSSHWindowAndPromotesAtomically(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	state, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	sshClassifier, err := classifier.NewSSHClassifier(classifier.DefaultSSHConfig())
	if err != nil {
		t.Fatal(err)
	}
	httpClassifier, err := classifier.NewHTTPClassifier(classifier.DefaultHTTPConfig())
	if err != nil {
		t.Fatal(err)
	}
	processor, err := NewProcessor(state, sshClassifier, httpClassifier)
	if err != nil {
		t.Fatal(err)
	}

	start := time.Date(2026, 9, 10, 19, 0, 0, 0, time.UTC)
	for i := range 5 {
		if err := processor.Process(ctx, "openssh", sshObservation(i, start.Add(time.Duration(i)*time.Minute))); err != nil {
			t.Fatal(err)
		}
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}

	state, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	sshClassifier, err = classifier.NewSSHClassifier(classifier.DefaultSSHConfig())
	if err != nil {
		t.Fatal(err)
	}
	processor, err = NewProcessor(state, sshClassifier, httpClassifier)
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RestoreSSH(ctx, start, 100); err != nil {
		t.Fatal(err)
	}
	if err := processor.Process(ctx, "openssh", sshObservation(5, start.Add(5*time.Minute))); err != nil {
		t.Fatal(err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := state.CreatePendingBatch(
		ctx,
		testBatchConfig(privateKey),
		start.Add(time.Hour),
		start.Add(30*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := protocol.DecodeSignedBatch(pending.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.VerifyBatch(batch, publicKey); err != nil {
		t.Fatal(err)
	}
	if len(batch.Payload.Records) != 1 || batch.Payload.Records[0].Count != 6 {
		t.Fatalf("restored threshold batch records = %#v", batch.Payload.Records)
	}
}

func TestProcessorDropsOrdinaryHTTPAndStripsProbeQuery(t *testing.T) {
	ctx := context.Background()
	state, processor := testProcessor(t, classifier.DefaultSSHConfig())
	start := time.Date(2026, 9, 10, 19, 0, 0, 0, time.UTC)

	ordinary := httpObservation("http-1", "line-1", start, "/missing?email=user@example.test")
	if err := processor.Process(ctx, "nginx", ordinary); err != nil {
		t.Fatal(err)
	}
	probe := httpObservation("http-2", "line-2", start.Add(time.Minute), "/a/../etc/passwd?token=private")
	if err := processor.Process(ctx, "nginx", probe); err != nil {
		t.Fatal(err)
	}

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := state.CreatePendingBatch(
		ctx,
		testBatchConfig(privateKey),
		start.Add(time.Hour),
		start.Add(30*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := protocol.DecodeSignedBatch(pending.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Payload.Records) != 1 || batch.Payload.Records[0].Path != "/a/../etc/passwd" {
		t.Fatalf("HTTP batch records = %#v", batch.Payload.Records)
	}
}

func TestProcessorAdvancesExcludedSSHCursorWithoutStoringEvent(t *testing.T) {
	ctx := context.Background()
	config := classifier.DefaultSSHConfig()
	config.ExcludedUsernames = []string{"deploy"}
	state, processor := testProcessor(t, config)
	observation := sshObservation(0, time.Date(2026, 9, 10, 19, 0, 0, 0, time.UTC))
	observation.SSH.Username = "deploy"

	if err := processor.Process(ctx, "openssh", observation); err != nil {
		t.Fatal(err)
	}
	cursor, found, err := state.Cursor(ctx, "openssh")
	if err != nil || !found || cursor != observation.Cursor {
		t.Fatalf("excluded SSH cursor = %q, %v, %v", cursor, found, err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = state.CreatePendingBatch(
		ctx,
		testBatchConfig(privateKey),
		time.Date(2026, 9, 10, 20, 0, 0, 0, time.UTC),
		time.Date(2026, 9, 10, 19, 30, 0, 0, time.UTC),
	)
	if !errors.Is(err, store.ErrNoPromotedObservations) {
		t.Fatalf("excluded SSH observation entered a batch: %v", err)
	}
}

func TestProcessorFailsClosedAfterStoreError(t *testing.T) {
	ctx := context.Background()
	state, processor := testProcessor(t, classifier.DefaultSSHConfig())
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	observation := sshObservation(0, time.Date(2026, 9, 10, 19, 0, 0, 0, time.UTC))
	if err := processor.Process(ctx, "openssh", observation); err == nil {
		t.Fatal("processor accepted an observation after the store closed")
	}
	if err := processor.Process(ctx, "openssh", observation); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("processor did not remain poisoned: %v", err)
	}
}

func testProcessor(t *testing.T, sshConfig classifier.SSHConfig) (*store.Store, *Processor) {
	t.Helper()
	state, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = state.Close()
	})
	sshClassifier, err := classifier.NewSSHClassifier(sshConfig)
	if err != nil {
		t.Fatal(err)
	}
	httpClassifier, err := classifier.NewHTTPClassifier(classifier.DefaultHTTPConfig())
	if err != nil {
		t.Fatal(err)
	}
	processor, err := NewProcessor(state, sshClassifier, httpClassifier)
	if err != nil {
		t.Fatal(err)
	}
	return state, processor
}

func sshObservation(index int, observedAt time.Time) protocol.Observation {
	return protocol.Observation{
		SchemaVersion: protocol.ObservationSchemaVersion,
		EventID:       fmt.Sprintf("ssh-%d", index),
		Cursor:        fmt.Sprintf("cursor-%d", index),
		Kind:          protocol.ObservationSSHAuthFailure,
		ObservedAt:    observedAt.Format(time.RFC3339Nano),
		SourceIP:      "2001:db8::10",
		SSH:           &protocol.SSHObservation{Username: "root"},
	}
}

func httpObservation(eventID, cursor string, observedAt time.Time, target string) protocol.Observation {
	return protocol.Observation{
		SchemaVersion: protocol.ObservationSchemaVersion,
		EventID:       eventID,
		Cursor:        cursor,
		Kind:          protocol.ObservationHTTPRequest,
		ObservedAt:    observedAt.Format(time.RFC3339Nano),
		SourceIP:      "192.0.2.10",
		HTTP: &protocol.HTTPObservation{
			RequestTarget: target,
			Status:        404,
		},
	}
}

func testBatchConfig(privateKey ed25519.PrivateKey) store.BatchConfig {
	return store.BatchConfig{
		SourceID:          "sensor-one",
		SourceEpoch:       "5d6079de-20e0-4d4b-b955-40eac8f14df8",
		ClassifierVersion: "classifier-v1",
		KeyID:             "key-1",
		PrivateKey:        privateKey,
	}
}
