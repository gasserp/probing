package adapter

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestDecoderRequiresHelloFirst(t *testing.T) {
	decoder := NewDecoder(strings.NewReader(`{"type":"ack","ack":{"event_id":"one","cursor":"one"}}`+"\n"), 1024)
	if _, err := decoder.Next(); err == nil {
		t.Fatal("decoder accepted acknowledgement before hello")
	}
}

func TestDecoderReadsNegotiationThenObservation(t *testing.T) {
	input := strings.Join([]string{
		`{"type":"hello","hello":{"protocol_versions":["probing.adapter/v1"],"adapter_name":"test","adapter_version":"1.0.0"}}`,
		`{"type":"observation","observation":{"schema_version":"probing.observation/v1","event_id":"event-1","cursor":"cursor-1","kind":"ssh_auth_failure","observed_at":"2026-09-10T19:00:00Z","source_ip":"2001:db8::1","ssh":{"username":"root"}}}`,
		"",
	}, "\n")
	decoder := NewDecoder(strings.NewReader(input), 4096)

	if frame, err := decoder.Next(); err != nil || frame.Type != FrameHello {
		t.Fatalf("hello frame = %#v, %v", frame, err)
	}
	if decoder.SelectedVersion() != "probing.adapter/v1" {
		t.Fatalf("selected version = %q", decoder.SelectedVersion())
	}
	if frame, err := decoder.Next(); err != nil || frame.Type != FrameObservation {
		t.Fatalf("observation frame = %#v, %v", frame, err)
	}
	if _, err := decoder.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("end of stream error = %v, want EOF", err)
	}
}

func TestDecoderRejectsOversizedAndTrailingFrames(t *testing.T) {
	oversized := `{"type":"hello","hello":{"protocol_versions":["probing.adapter/v1"],"adapter_name":"` +
		strings.Repeat("a", 200) + `","adapter_version":"1"}}` + "\n"
	if _, err := NewDecoder(strings.NewReader(oversized), 128).Next(); err == nil {
		t.Fatal("decoder accepted oversized frame")
	}

	trailing := `{"type":"hello","hello":{"protocol_versions":["probing.adapter/v1"],"adapter_name":"test","adapter_version":"1"}} true` + "\n"
	if _, err := NewDecoder(strings.NewReader(trailing), 1024).Next(); err == nil {
		t.Fatal("decoder accepted trailing JSON")
	}

	unsupported := `{"type":"hello","hello":{"protocol_versions":["probing.adapter/v2"],"adapter_name":"test","adapter_version":"1"}}` + "\n"
	if _, err := NewDecoder(strings.NewReader(unsupported), 1024).Next(); err == nil {
		t.Fatal("decoder accepted an unsupported protocol")
	}

	invalidUTF8 := append([]byte(`{"type":"hello","hello":{"protocol_versions":["probing.adapter/v1"],"adapter_name":"`), 0xff)
	invalidUTF8 = append(invalidUTF8, []byte(`","adapter_version":"1"}}`+"\n")...)
	if _, err := NewDecoder(strings.NewReader(string(invalidUTF8)), 1024).Next(); err == nil {
		t.Fatal("decoder accepted invalid UTF-8")
	}
}

func TestControlDecoderRequiresResumeThenAcknowledgements(t *testing.T) {
	input := strings.Join([]string{
		`{"type":"resume","resume":{"cursor":"cursor-1"}}`,
		`{"type":"ack","ack":{"event_id":"event-2","cursor":"cursor-2"}}`,
		`{"type":"ack","ack":{"cursor":"cursor-3"}}`,
		"",
	}, "\n")
	decoder := NewControlDecoder(strings.NewReader(input), 1024)
	if frame, err := decoder.Next(); err != nil || frame.Type != FrameResume {
		t.Fatalf("resume frame = %#v, %v", frame, err)
	}
	for range 2 {
		if frame, err := decoder.Next(); err != nil || frame.Type != FrameAck {
			t.Fatalf("ack frame = %#v, %v", frame, err)
		}
	}

	invalid := NewControlDecoder(
		strings.NewReader(`{"type":"ack","ack":{"cursor":"cursor-1"}}`+"\n"),
		1024,
	)
	if _, err := invalid.Next(); err == nil {
		t.Fatal("control decoder accepted acknowledgement before resume")
	}
}
