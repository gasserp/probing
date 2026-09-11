package publication

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/gasserp/probing/protocol"
)

func TestEnvelopeAndReceiptAreStrictAndDeterministic(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := protocol.SignBatch(testPayload(), "key-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := ValidateEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.FileName == "" ||
		envelope.BlobName != "sensor-one/5d6079de-20e0-4d4b-b955-40eac8f14df8/1-0/"+envelope.PayloadHash+".json" {
		t.Fatalf("unexpected deterministic names: %#v", envelope)
	}
	if _, err := ValidateEnvelope(append(data, '\n')); err == nil {
		t.Fatal("accepted a transport-reencoded envelope")
	}
	receipt := Receipt{
		SchemaVersion:  ReceiptSchemaVersion,
		SourceID:       batch.Payload.SourceID,
		SourceEpoch:    batch.Payload.SourceEpoch,
		Sequence:       batch.Payload.Sequence,
		PayloadHash:    envelope.PayloadHash,
		EnvelopeSHA256: envelope.EnvelopeSHA256,
		BlobName:       envelope.BlobName,
		ETag:           `"0x8DABC123"`,
	}
	encoded, err := EncodeReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeReceipt(encoded); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeReceipt(append(encoded, '\n')); err == nil {
		t.Fatal("accepted a transport-reencoded receipt")
	}
}

func testPayload() protocol.BatchPayload {
	return protocol.BatchPayload{
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
			Count:           1,
			FirstObservedAt: "2026-09-10T19:01:00Z",
			LastObservedAt:  "2026-09-10T19:01:00Z",
			HourlyBuckets:   []protocol.HourlyBucket{{Hour: "2026-09-10T19:00:00Z", Count: 1}},
			RuleIDs:         []string{"ssh/pair-threshold-v1"},
		}},
	}
}
