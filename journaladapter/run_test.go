package journaladapter

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/gasserp/probing/adapter"
	"github.com/gasserp/probing/source/openssh"
)

func journalRecord(t *testing.T, cursor, message string) string {
	t.Helper()
	data, err := json.Marshal(map[string]string{
		"__CURSOR":             cursor,
		"__REALTIME_TIMESTAMP": "1789066862000000",
		"_BOOT_ID":             "0123456789abcdef0123456789abcdef",
		"MESSAGE":              message,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(data) + "\n"
}

type opening struct {
	cursor string
	follow bool
}

type session struct {
	decoder *adapter.Decoder
	control *io.PipeWriter
	result  chan error
	opened  chan opening
}

// start runs the adapter against a fake journal. stored is what a resume
// drains without following; followed is what the following stream yields.
func start(t *testing.T, stored, followed, resume string, diagnostics io.Writer) *session {
	t.Helper()
	controlReader, controlWriter := io.Pipe()
	outputReader, outputWriter := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	s := &session{
		decoder: adapter.NewDecoder(outputReader, adapter.DefaultMaxFrameBytes),
		control: controlWriter,
		result:  make(chan error, 1),
		opened:  make(chan opening, 2),
	}
	source := func(_ context.Context, cursor string, follow bool) (io.ReadCloser, error) {
		s.opened <- opening{cursor: cursor, follow: follow}
		if follow {
			return io.NopCloser(strings.NewReader(followed)), nil
		}
		return io.NopCloser(strings.NewReader(stored)), nil
	}
	go func() {
		err := Run(ctx, Config{Name: "openssh", Version: "1.0.0", Diagnostics: diagnostics},
			source, openssh.Parse, controlReader, outputWriter)
		_ = outputWriter.CloseWithError(err)
		s.result <- err
	}()
	if frame, err := s.decoder.Next(); err != nil || frame.Type != adapter.FrameHello {
		t.Fatalf("hello = %#v, %v", frame, err)
	}
	if err := adapter.Encode(controlWriter, adapter.Frame{
		Type:   adapter.FrameResume,
		Resume: &adapter.Resume{Cursor: resume},
	}); err != nil {
		t.Fatal(err)
	}
	return s
}

func (s *session) next(t *testing.T) adapter.Frame {
	t.Helper()
	frame, err := s.decoder.Next()
	if err != nil {
		t.Fatal(err)
	}
	ack := adapter.Ack{}
	switch frame.Type {
	case adapter.FrameObservation:
		ack = adapter.Ack{EventID: frame.Observation.EventID, Cursor: frame.Observation.Cursor}
	case adapter.FrameCheckpoint:
		ack = adapter.Ack{Cursor: frame.Checkpoint.Cursor}
	default:
		t.Fatalf("unexpected frame type %q", frame.Type)
	}
	if err := adapter.Encode(s.control, adapter.Frame{Type: adapter.FrameAck, Ack: &ack}); err != nil {
		t.Fatal(err)
	}
	return frame
}

func TestRunEmitsObservationsAndCheckpointsEveryRecord(t *testing.T) {
	stored := journalRecord(t, "s=ab;i=1", "Invalid user admin from 192.0.2.12 port 4242") +
		journalRecord(t, "s=ab;i=2", "Failed password for invalid user admin from 192.0.2.12 port 4242 ssh2")
	followed := `{"__CURSOR":"s=ab;i=3","__REALTIME_TIMESTAMP":"1789066862000000","MESSAGE":[70,97,105,108]}` + "\n"
	var diagnostics bytes.Buffer
	s := start(t, stored, followed, "s=ab;i=0", &diagnostics)
	if opened := <-s.opened; opened != (opening{cursor: "s=ab;i=0"}) {
		t.Fatalf("resume drained from %+v", opened)
	}

	if frame := s.next(t); frame.Type != adapter.FrameCheckpoint || frame.Checkpoint.Cursor != "s=ab;i=1" {
		t.Fatalf("first frame = %#v", frame)
	}
	frame := s.next(t)
	if frame.Type != adapter.FrameObservation || frame.Observation.Cursor != "s=ab;i=2" ||
		frame.Observation.SourceIP != "192.0.2.12" || frame.Observation.SSH.Username != "admin" {
		t.Fatalf("second frame = %#v", frame)
	}
	if opened := <-s.opened; opened != (opening{cursor: "s=ab;i=2", follow: true}) {
		t.Fatalf("follow opened at %+v, want after the last drained record", opened)
	}
	if frame := s.next(t); frame.Type != adapter.FrameCheckpoint || frame.Checkpoint.Cursor != "s=ab;i=3" {
		t.Fatalf("undecodable record was not checkpointed: %#v", frame)
	}
	if err := <-s.result; err == nil || !strings.Contains(err.Error(), "journal stream ended") {
		t.Fatalf("Run() error = %v", err)
	}
	if !strings.Contains(diagnostics.String(), "ignored invalid openssh record") {
		t.Fatalf("diagnostics = %q", diagnostics.String())
	}
}

func TestRunStartsAtJournalEndWithoutResumeCursor(t *testing.T) {
	s := start(t, "", "", "", io.Discard)
	if opened := <-s.opened; opened != (opening{follow: true}) {
		t.Fatalf("source opened at %+v", opened)
	}
	<-s.result
}

func TestRunFollowsFromResumeCursorWhenNothingIsStored(t *testing.T) {
	s := start(t, "", "", "s=ab;i=9", io.Discard)
	<-s.opened
	if opened := <-s.opened; opened != (opening{cursor: "s=ab;i=9", follow: true}) {
		t.Fatalf("follow opened at %+v", opened)
	}
	<-s.result
}

func TestRunRejectsForeignResumeCursor(t *testing.T) {
	s := start(t, "", "", "file-v1:1:2:3", io.Discard)
	if err := <-s.result; err == nil || !strings.Contains(err.Error(), "not a journal cursor") {
		t.Fatalf("Run() error = %v", err)
	}
	select {
	case cursor := <-s.opened:
		t.Fatalf("source opened at %+v", cursor)
	default:
	}
}

func TestRunSkipsOversizedRecordWithoutCheckpoint(t *testing.T) {
	huge := `{"__CURSOR":"s=ab;i=1","MESSAGE":"` + strings.Repeat("x", MaxRecordBytes) + `"}` + "\n"
	records := huge + journalRecord(t, "s=ab;i=2", "Accepted publickey for pi from 192.0.2.1 port 1 ssh2")
	var diagnostics bytes.Buffer
	s := start(t, "", records, "", &diagnostics)
	<-s.opened
	if frame := s.next(t); frame.Type != adapter.FrameCheckpoint || frame.Checkpoint.Cursor != "s=ab;i=2" {
		t.Fatalf("frame = %#v", frame)
	}
	<-s.result
	if !strings.Contains(diagnostics.String(), "skipped journal record") {
		t.Fatalf("diagnostics = %q", diagnostics.String())
	}
}

func TestRunStopsOnRecordWithoutCursor(t *testing.T) {
	s := start(t, "", `{"MESSAGE":"no cursor"}`+"\n", "", io.Discard)
	<-s.opened
	if err := <-s.result; err == nil || !strings.Contains(err.Error(), "__CURSOR") {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestValidCursor(t *testing.T) {
	valid := "s=739ad463348b4ceca5a9e69c95a3c93f;i=4ece7;b=6c7c6013a8314c1e8b3b3c1a0b6d5c2a;m=21d6c5f8;t=5f6a4c1b2a3d4;x=9b3b1a2c3d4e5f60"
	if !ValidCursor(valid) {
		t.Fatal("real journal cursor rejected")
	}
	for _, cursor := range []string{"", "--since=yesterday", "s=ab;i=1\n", "file-v1:1:2:3", "s=AB"} {
		if ValidCursor(cursor) {
			t.Fatalf("ValidCursor(%q) = true", cursor)
		}
	}
}
