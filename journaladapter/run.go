// Package journaladapter streams systemd journal records to the collector.
//
// Unlike a log file, the journal has its own durable position: every record
// carries an opaque __CURSOR. The adapter uses that cursor as the source
// cursor, so a collector restart resumes right after the last acknowledged
// record regardless of journal rotation or vacuuming.
package journaladapter

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/gasserp/probing/adapter"
	"github.com/gasserp/probing/protocol"
)

// MaxRecordBytes bounds one journalctl JSON record. journalctl replaces any
// field over 4 KiB with null in JSON output, so a record limited to a few
// fields stays far below this; a longer one is skipped, not fatal.
const MaxRecordBytes = 256 * 1024

var cursorPattern = regexp.MustCompile(`^[a-z]+=[0-9a-f]+(?:;[a-z]+=[0-9a-f]+)*$`)

// Source opens a journal record stream positioned just after cursor, or at
// the current end of the journal when cursor is empty. The stream is one JSON
// object per line, as `journalctl --output=json` prints it. A stream opened
// with follow keeps waiting for new records; without follow it ends after the
// last stored record.
type Source func(ctx context.Context, cursor string, follow bool) (io.ReadCloser, error)

// Parser turns one journal record into an observation. It returns false for
// records that are not observations and an error for records it cannot read.
type Parser func(record []byte) (protocol.Observation, bool, error)

type Config struct {
	Name        string
	Version     string
	Diagnostics io.Writer
}

// ValidCursor reports whether cursor has the shape of a systemd journal
// cursor. It keeps a foreign or corrupted resume value from reaching
// journalctl.
func ValidCursor(cursor string) bool {
	return len(cursor) <= protocol.MaxCursorBytes && cursorPattern.MatchString(cursor)
}

func Run(ctx context.Context, config Config, open Source, parser Parser, control io.Reader, output io.Writer) error {
	if config.Name == "" || config.Version == "" || open == nil || parser == nil {
		return errors.New("adapter name, version, source, and parser are required")
	}
	if config.Diagnostics == nil {
		config.Diagnostics = io.Discard
	}
	if err := adapter.Encode(output, adapter.Frame{
		Type: adapter.FrameHello,
		Hello: &adapter.Hello{
			ProtocolVersions: []string{protocol.AdapterProtocolVersion},
			AdapterName:      config.Name,
			AdapterVersion:   config.Version,
		},
	}); err != nil {
		return err
	}
	controlDecoder := adapter.NewControlDecoder(control, adapter.DefaultMaxFrameBytes)
	resume, err := controlDecoder.Next()
	if err != nil {
		return fmt.Errorf("read resume cursor: %w", err)
	}
	cursor := resume.Resume.Cursor
	if cursor != "" && !ValidCursor(cursor) {
		return errors.New("resume cursor is not a journal cursor")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// journalctl --follow can skip records after the cursor that live in an
	// older boot's journal file, so a resume first drains everything stored
	// after the cursor and only then follows from the last record it saw.
	if cursor != "" {
		cursor, err = stream(ctx, config, open, cursor, false, parser, controlDecoder, output)
		if err != nil {
			return err
		}
	}
	_, err = stream(ctx, config, open, cursor, true, parser, controlDecoder, output)
	return err
}

func stream(
	ctx context.Context,
	config Config,
	open Source,
	cursor string,
	follow bool,
	parser Parser,
	control *adapter.ControlDecoder,
	output io.Writer,
) (string, error) {
	records, err := open(ctx, cursor, follow)
	if err != nil {
		return "", fmt.Errorf("open journal: %w", err)
	}
	defer records.Close()
	reader := bufio.NewReaderSize(records, 64*1024)
	for {
		record, err := readRecord(reader)
		if err != nil && ctx.Err() != nil {
			return "", ctx.Err()
		}
		if errors.Is(err, errRecordTooLong) {
			fmt.Fprintf(config.Diagnostics, "skipped journal record over %d bytes\n", MaxRecordBytes)
			continue
		}
		if errors.Is(err, io.EOF) {
			if follow {
				return "", errors.New("journal stream ended")
			}
			return cursor, nil
		}
		if err != nil {
			return "", fmt.Errorf("read journal: %w", err)
		}
		cursor, err = emitRecord(config, record, parser, control, output)
		if err != nil {
			return "", err
		}
	}
}

var errRecordTooLong = errors.New("journal record is too long")

func readRecord(reader *bufio.Reader) ([]byte, error) {
	var record []byte
	tooLong := false
	for {
		fragment, err := reader.ReadSlice('\n')
		if !tooLong {
			if len(record)+len(fragment) > MaxRecordBytes {
				tooLong = true
				record = nil
			} else {
				record = append(record, fragment...)
			}
		}
		switch {
		case err == nil && tooLong:
			return nil, errRecordTooLong
		case err == nil:
			return record[:len(record)-1], nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && len(record) != 0:
			return nil, errors.New("journal stream ended inside a record")
		default:
			return nil, err
		}
	}
}

func emitRecord(
	config Config,
	record []byte,
	parser Parser,
	control *adapter.ControlDecoder,
	output io.Writer,
) (string, error) {
	// Only the cursor is decoded here; the rest of the record is the parser's
	// business and may legitimately fail to decode (for example, a MESSAGE
	// that journalctl renders as a byte array).
	var position struct {
		Cursor string `json:"__CURSOR"`
	}
	if err := json.Unmarshal(record, &position); err != nil || !ValidCursor(position.Cursor) {
		return "", errors.New("journal record has no valid __CURSOR")
	}
	cursor := position.Cursor

	observation, matched, err := parser(record)
	if err != nil {
		fmt.Fprintf(config.Diagnostics, "ignored invalid %s record: %q\n", config.Name, err.Error())
		matched = false
	}
	if matched && observation.Cursor != cursor {
		return "", errors.New("parser changed the journal cursor")
	}
	frame := adapter.Frame{Type: adapter.FrameCheckpoint, Checkpoint: &adapter.Checkpoint{Cursor: cursor}}
	eventID := ""
	if matched {
		frame = adapter.Frame{Type: adapter.FrameObservation, Observation: &observation}
		eventID = observation.EventID
	}
	if err := adapter.Encode(output, frame); err != nil {
		return "", err
	}
	ack, err := control.Next()
	if err != nil {
		return "", fmt.Errorf("read acknowledgement: %w", err)
	}
	if ack.Type == adapter.FrameError {
		return "", fmt.Errorf("core rejected input with %s: %s", ack.Error.Code, ack.Error.Message)
	}
	if ack.Type != adapter.FrameAck || ack.Ack.Cursor != cursor || ack.Ack.EventID != eventID {
		return "", errors.New("core acknowledgement does not match emitted input")
	}
	return cursor, nil
}
