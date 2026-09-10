package protocol

import "testing"

func TestValidateObservation(t *testing.T) {
	observation := Observation{
		SchemaVersion: ObservationSchemaVersion,
		EventID:       "journal:1234",
		Cursor:        "s=cursor;i=1234",
		Kind:          ObservationSSHAuthFailure,
		ObservedAt:    "2026-09-10T19:05:00Z",
		SourceIP:      "192.0.2.10",
		SSH:           &SSHObservation{Username: "admin"},
	}
	if err := ValidateObservation(observation); err != nil {
		t.Fatalf("ValidateObservation() error = %v", err)
	}

	observation.HTTP = &HTTPObservation{RequestTarget: "/../etc/passwd", Status: 404}
	if err := ValidateObservation(observation); err == nil {
		t.Fatal("ValidateObservation() accepted multiple payloads")
	}
}

func TestValidateBatchRequiresPreviousHashAfterSequenceZero(t *testing.T) {
	payload := validBatchPayload()
	payload.Sequence = "1"
	if err := ValidateBatchPayload(payload); err == nil {
		t.Fatal("ValidateBatchPayload() accepted a missing previous hash")
	}
}

func TestValidateObservationRequiresCanonicalAddress(t *testing.T) {
	observation := Observation{
		SchemaVersion: ObservationSchemaVersion,
		EventID:       "journal:1234",
		Cursor:        "s=cursor;i=1234",
		Kind:          ObservationSSHAuthFailure,
		ObservedAt:    "2026-09-10T19:05:00Z",
		SourceIP:      "::ffff:192.0.2.10",
		SSH:           &SSHObservation{Username: "admin"},
	}
	if err := ValidateObservation(observation); err == nil {
		t.Fatal("ValidateObservation() accepted an IPv4-mapped IPv6 address")
	}

	observation.SourceIP = "fe80::1%eth0"
	if err := ValidateObservation(observation); err == nil {
		t.Fatal("ValidateObservation() accepted a zoned IPv6 address")
	}
}

func TestValidateBatchRequiresBucketsAtRecordBoundaries(t *testing.T) {
	payload := validBatchPayload()
	payload.ObservationWindow.Start = "2026-09-10T18:00:00Z"
	payload.Records[0].HourlyBuckets[0].Hour = "2026-09-10T18:00:00Z"
	if err := ValidateBatchPayload(payload); err == nil {
		t.Fatal("ValidateBatchPayload() accepted a bucket before the first observation hour")
	}
}
