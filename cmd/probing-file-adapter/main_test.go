package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/gasserp/probing/protocol"
)

func TestRecoverInvalidRecordsCheckpointsRejectedLine(t *testing.T) {
	var diagnostics bytes.Buffer
	parser := recoverInvalidRecords("nginx", func([]byte, string) (protocol.Observation, bool, error) {
		return protocol.Observation{}, false, errors.New("log line is not valid UTF-8")
	}, &diagnostics)

	observation, matched, err := parser([]byte{0xff}, "cursor")
	if err != nil {
		t.Fatal(err)
	}
	if matched || observation != (protocol.Observation{}) {
		t.Fatal("invalid record produced an observation")
	}
	if !strings.Contains(diagnostics.String(), `ignored invalid nginx record: "log line is not valid UTF-8"`) {
		t.Fatalf("diagnostics = %q", diagnostics.String())
	}
}

func TestRecoverInvalidRecordsPreservesValidObservation(t *testing.T) {
	want := protocol.Observation{EventID: "event"}
	parser := recoverInvalidRecords("nginx", func([]byte, string) (protocol.Observation, bool, error) {
		return want, true, nil
	}, &bytes.Buffer{})

	got, matched, err := parser([]byte(`{}`), "cursor")
	if err != nil {
		t.Fatal(err)
	}
	if !matched || got != want {
		t.Fatalf("got (%+v, %t), want (%+v, true)", got, matched, want)
	}
}
