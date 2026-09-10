package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
)

func TestSignAndVerifyBatch(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := validBatchPayload()

	batch, err := SignBatch(payload, "sensor-key-1", privateKey)
	if err != nil {
		t.Fatalf("SignBatch() error = %v", err)
	}
	if err := VerifyBatch(batch, publicKey); err != nil {
		t.Fatalf("VerifyBatch() error = %v", err)
	}

	batch.Payload.Records[0].Username = "tampered"
	if err := VerifyBatch(batch, publicKey); err == nil {
		t.Fatal("VerifyBatch() accepted a tampered payload")
	}
}

func TestPayloadHashUsesDomainSeparatedCanonicalJSON(t *testing.T) {
	payload := validBatchPayload()
	hash, err := PayloadHash(payload)
	if err != nil {
		t.Fatalf("PayloadHash() error = %v", err)
	}
	if len(hash) != 64 {
		t.Fatalf("PayloadHash() length = %d, want 64", len(hash))
	}

	message, err := SigningBytes(payload)
	if err != nil {
		t.Fatalf("SigningBytes() error = %v", err)
	}
	if !strings.HasPrefix(string(message), signingDomain+`{"classifier_version"`) {
		t.Fatalf("SigningBytes() did not contain domain-separated canonical JSON: %q", message)
	}
}

func TestValidateBatchRejectsInconsistentBucketCount(t *testing.T) {
	payload := validBatchPayload()
	payload.Records[0].HourlyBuckets[0].Count = 5
	if err := ValidateBatchPayload(payload); err == nil {
		t.Fatal("ValidateBatchPayload() accepted inconsistent hourly counts")
	}
}

func TestValidateBatchRejectsUnsafeJSONInteger(t *testing.T) {
	payload := validBatchPayload()
	payload.Records[0].Count = MaxSafeJSONInteger + 1
	payload.Records[0].HourlyBuckets[0].Count = MaxSafeJSONInteger + 1
	if err := ValidateBatchPayload(payload); err == nil {
		t.Fatal("ValidateBatchPayload() accepted an integer unsafe for RFC 8785")
	}
}

func TestDecodeSignedBatchRejectsUnknownAndTrailingData(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := SignBatch(validBatchPayload(), "key-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSignedBatch(encoded)
	if err != nil {
		t.Fatalf("DecodeSignedBatch() error = %v", err)
	}
	if err := VerifyBatch(decoded, publicKey); err != nil {
		t.Fatalf("VerifyBatch() error = %v", err)
	}

	if _, err := DecodeSignedBatch(append(encoded, []byte(" true")...)); err == nil {
		t.Fatal("DecodeSignedBatch() accepted trailing JSON")
	}
	if _, err := DecodeSignedBatch([]byte("{\"payload\":\xff}")); err == nil {
		t.Fatal("DecodeSignedBatch() accepted invalid UTF-8")
	}
}

func TestSignBatchRejectsOversizedKeyID(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignBatch(validBatchPayload(), strings.Repeat("k", MaxKeyIDBytes+1), privateKey); err == nil {
		t.Fatal("SignBatch() accepted an oversized key ID")
	}
}

func validBatchPayload() BatchPayload {
	return BatchPayload{
		SchemaVersion:     BatchSchemaVersion,
		SourceID:          "sensor-one",
		SourceEpoch:       "5d6079de-20e0-4d4b-b955-40eac8f14df8",
		Sequence:          "0",
		CreatedAt:         "2026-09-10T20:00:00Z",
		ClassifierVersion: "classifier-v1",
		ObservationWindow: TimeRange{
			Start: "2026-09-10T19:00:00Z",
			End:   "2026-09-10T20:00:00Z",
		},
		Records: []BatchRecord{{
			Kind:            ObservationSSHAuthFailure,
			SourceIP:        "2001:db8::42",
			Username:        "root",
			Count:           6,
			FirstObservedAt: "2026-09-10T19:05:00Z",
			LastObservedAt:  "2026-09-10T19:10:00Z",
			HourlyBuckets: []HourlyBucket{{
				Hour:  "2026-09-10T19:00:00Z",
				Count: 6,
			}},
			RuleIDs: []string{"ssh/pair-threshold-v1"},
		}},
	}
}
