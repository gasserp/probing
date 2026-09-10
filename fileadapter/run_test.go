package fileadapter

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gasserp/probing/adapter"
	"github.com/gasserp/probing/protocol"
)

func TestRunEmitsAndResumesFromAcknowledgedCursor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.jsonl")
	if err := os.WriteFile(path, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	parser := func(line []byte, cursor string) (protocol.Observation, bool, error) {
		return protocol.Observation{
			SchemaVersion: protocol.ObservationSchemaVersion,
			EventID:       "event-1",
			Cursor:        cursor,
			Kind:          protocol.ObservationHTTPRequest,
			ObservedAt:    "2026-09-10T19:00:00Z",
			SourceIP:      "192.0.2.1",
			HTTP: &protocol.HTTPObservation{
				RequestTarget: "/../etc/passwd",
				Status:        404,
			},
		}, true, nil
	}

	cursor := runOnce(t, path, "", parser, true)
	if cursor == "" {
		t.Fatal("adapter did not emit a cursor")
	}
	runOnce(t, path, cursor, parser, false)
}

func runOnce(t *testing.T, path, resumeCursor string, parser Parser, expectObservation bool) string {
	t.Helper()
	controlReader, controlWriter := io.Pipe()
	outputReader, outputWriter := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := make(chan error, 1)
	go func() {
		err := Run(ctx, Config{
			Name:    "test",
			Version: "1.0.0",
			Path:    path,
			Once:    true,
		}, parser, controlReader, outputWriter)
		_ = outputWriter.CloseWithError(err)
		result <- err
	}()

	decoder := adapter.NewDecoder(outputReader, adapter.DefaultMaxFrameBytes)
	if frame, err := decoder.Next(); err != nil || frame.Type != adapter.FrameHello {
		t.Fatalf("hello = %#v, %v", frame, err)
	}
	if err := adapter.Encode(controlWriter, adapter.Frame{
		Type:   adapter.FrameResume,
		Resume: &adapter.Resume{Cursor: resumeCursor},
	}); err != nil {
		t.Fatal(err)
	}

	cursor := ""
	if expectObservation {
		frame, err := decoder.Next()
		if err != nil {
			t.Fatal(err)
		}
		if frame.Type != adapter.FrameObservation {
			t.Fatalf("frame type = %q", frame.Type)
		}
		cursor = frame.Observation.Cursor
		if err := adapter.Encode(controlWriter, adapter.Frame{
			Type: adapter.FrameAck,
			Ack:  &adapter.Ack{EventID: frame.Observation.EventID, Cursor: cursor},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	return cursor
}
