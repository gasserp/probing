package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gasserp/probing/protocol"
	"github.com/gasserp/probing/publication"
	"github.com/gasserp/probing/store"
)

func TestBatchPublisherRoundTripsUploaderReceipt(t *testing.T) {
	root := t.TempDir()
	outbox := filepath.Join(root, "outbox")
	if err := os.Mkdir(outbox, 0o750); err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(root, "key.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	epochPath := filepath.Join(root, "epoch")
	if err := os.WriteFile(epochPath, []byte("5d6079de-20e0-4d4b-b955-40eac8f14df8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	state, err := store.Open(filepath.Join(root, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	observation := protocol.Observation{
		SchemaVersion: protocol.ObservationSchemaVersion,
		EventID:       "event-1",
		Cursor:        "cursor-1",
		Kind:          protocol.ObservationSSHAuthFailure,
		ObservedAt:    "2026-09-10T19:01:00Z",
		SourceIP:      "2001:db8::1",
		SSH:           &protocol.SSHObservation{Username: "root"},
	}
	if _, err := state.CommitObservation(context.Background(), "ssh", store.ClassifiedObservation{
		Observation: observation,
	}, store.PromotionUpdate{
		EventID: observation.EventID,
		RuleIDs: []string{"ssh/pair-threshold-v1"},
	}); err != nil {
		t.Fatal(err)
	}
	publisher, err := newBatchPublisher(state, publicationConfig{
		SourceID:          "sensor-one",
		SourceEpochPath:   epochPath,
		PrivateKeyPath:    keyPath,
		KeyID:             "key-1",
		ClassifierVersion: "classifier-v1",
		OutboxDirectory:   outbox,
	}, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	publisher.now = func() time.Time {
		return time.Date(2026, 9, 10, 20, 0, 0, 0, time.UTC)
	}
	if err := publisher.pump(context.Background()); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(outbox)
	if err != nil || len(entries) != 1 {
		t.Fatalf("outbox after publish = %v, %v", entries, err)
	}
	envelopePath := filepath.Join(outbox, entries[0].Name())
	envelopeBytes, err := os.ReadFile(envelopePath)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := publication.ValidateEnvelope(envelopeBytes)
	if err != nil {
		t.Fatal(err)
	}
	receiptBytes, err := publication.EncodeReceipt(publication.Receipt{
		SchemaVersion:  publication.ReceiptSchemaVersion,
		SourceID:       envelope.Batch.Payload.SourceID,
		SourceEpoch:    envelope.Batch.Payload.SourceEpoch,
		Sequence:       envelope.Batch.Payload.Sequence,
		PayloadHash:    envelope.PayloadHash,
		EnvelopeSHA256: envelope.EnvelopeSHA256,
		BlobName:       envelope.BlobName,
		ETag:           `"0x8DABC123"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := publication.AtomicWrite(
		filepath.Join(outbox, publication.ReceiptFileName(envelope.FileName)),
		receiptBytes,
		0o640,
	); err != nil {
		t.Fatal(err)
	}
	receiptHash := sha256.Sum256(receiptBytes)
	if err := state.MarkBatchPublished(
		context.Background(),
		envelope.Batch.Payload.Sequence,
		envelope.PayloadHash,
		hex.EncodeToString(receiptHash[:]),
	); err != nil {
		t.Fatal(err)
	}
	if err := publisher.pump(context.Background()); err != nil {
		t.Fatal(err)
	}
	entries, err = os.ReadDir(outbox)
	if err != nil || len(entries) != 0 {
		t.Fatalf("outbox after acknowledgement = %v, %v", entries, err)
	}
	if _, found, err := state.NextPendingBatch(context.Background()); err != nil || found {
		t.Fatalf("pending batch after acknowledgement = %v, %v", found, err)
	}
}
