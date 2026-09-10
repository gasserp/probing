package adapter

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"unicode/utf8"

	"github.com/gasserp/probing/protocol"
)

const DefaultMaxFrameBytes = 64 * 1024

type FrameType string

const (
	FrameHello       FrameType = "hello"
	FrameObservation FrameType = "observation"
	FrameCheckpoint  FrameType = "checkpoint"
	FrameResume      FrameType = "resume"
	FrameAck         FrameType = "ack"
	FrameError       FrameType = "error"
)

type Frame struct {
	Type        FrameType             `json:"type"`
	Hello       *Hello                `json:"hello,omitempty"`
	Observation *protocol.Observation `json:"observation,omitempty"`
	Checkpoint  *Checkpoint           `json:"checkpoint,omitempty"`
	Resume      *Resume               `json:"resume,omitempty"`
	Ack         *Ack                  `json:"ack,omitempty"`
	Error       *AdapterError         `json:"error,omitempty"`
}

type Hello struct {
	ProtocolVersions []string `json:"protocol_versions"`
	AdapterName      string   `json:"adapter_name"`
	AdapterVersion   string   `json:"adapter_version"`
}

type Ack struct {
	EventID string `json:"event_id,omitempty"`
	Cursor  string `json:"cursor"`
}

type Checkpoint struct {
	Cursor string `json:"cursor"`
}

type Resume struct {
	Cursor string `json:"cursor,omitempty"`
}

type AdapterError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Decoder struct {
	scanner         *bufio.Scanner
	sawHello        bool
	selectedVersion string
}

type ControlDecoder struct {
	scanner   *bufio.Scanner
	sawResume bool
}

func NewDecoder(reader io.Reader, maxFrameBytes int) *Decoder {
	return &Decoder{scanner: newScanner(reader, maxFrameBytes)}
}

func NewControlDecoder(reader io.Reader, maxFrameBytes int) *ControlDecoder {
	return &ControlDecoder{scanner: newScanner(reader, maxFrameBytes)}
}

func newScanner(reader io.Reader, maxFrameBytes int) *bufio.Scanner {
	if maxFrameBytes <= 0 {
		maxFrameBytes = DefaultMaxFrameBytes
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, min(maxFrameBytes, 4096)), maxFrameBytes)
	return scanner
}

func (d *Decoder) Next() (Frame, error) {
	frame, err := nextFrame(d.scanner)
	if err != nil {
		return Frame{}, err
	}
	if !d.sawHello {
		if frame.Type != FrameHello {
			return Frame{}, errors.New("first adapter frame must be hello")
		}
		if !slices.Contains(frame.Hello.ProtocolVersions, protocol.AdapterProtocolVersion) {
			return Frame{}, fmt.Errorf("adapter does not support %s", protocol.AdapterProtocolVersion)
		}
		d.sawHello = true
		d.selectedVersion = protocol.AdapterProtocolVersion
	} else if frame.Type == FrameHello {
		return Frame{}, errors.New("hello frame may only appear first")
	}
	return frame, nil
}

func (d *ControlDecoder) Next() (Frame, error) {
	frame, err := nextFrame(d.scanner)
	if err != nil {
		return Frame{}, err
	}
	if !d.sawResume {
		if frame.Type != FrameResume {
			return Frame{}, errors.New("first core control frame must be resume")
		}
		d.sawResume = true
	} else if frame.Type != FrameAck && frame.Type != FrameError {
		return Frame{}, fmt.Errorf("invalid core control frame type %q", frame.Type)
	}
	return frame, nil
}

func nextFrame(scanner *bufio.Scanner) (Frame, error) {
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return Frame{}, fmt.Errorf("read adapter frame: %w", err)
		}
		return Frame{}, io.EOF
	}
	line := scanner.Bytes()
	if len(bytes.TrimSpace(line)) == 0 {
		return Frame{}, errors.New("empty adapter frame")
	}
	if !utf8.Valid(line) {
		return Frame{}, errors.New("adapter frame is not valid UTF-8")
	}
	var frame Frame
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&frame); err != nil {
		return Frame{}, fmt.Errorf("decode adapter frame: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Frame{}, errors.New("adapter frame contains trailing JSON")
	}
	if err := validateFrame(frame); err != nil {
		return Frame{}, err
	}
	return frame, nil
}

func (d *Decoder) SelectedVersion() string {
	return d.selectedVersion
}

func Encode(writer io.Writer, frame Frame) error {
	if err := validateFrame(frame); err != nil {
		return err
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	return encoder.Encode(frame)
}

func validateFrame(frame Frame) error {
	payloads := 0
	if frame.Hello != nil {
		payloads++
	}
	if frame.Observation != nil {
		payloads++
	}
	if frame.Checkpoint != nil {
		payloads++
	}
	if frame.Resume != nil {
		payloads++
	}
	if frame.Ack != nil {
		payloads++
	}
	if frame.Error != nil {
		payloads++
	}
	if payloads != 1 {
		return errors.New("adapter frame must contain exactly one payload")
	}

	switch frame.Type {
	case FrameHello:
		if frame.Hello == nil || len(frame.Hello.ProtocolVersions) == 0 ||
			frame.Hello.AdapterName == "" || frame.Hello.AdapterVersion == "" {
			return errors.New("invalid hello frame")
		}
	case FrameObservation:
		if frame.Observation == nil {
			return errors.New("observation frame is missing observation")
		}
		if err := protocol.ValidateObservation(*frame.Observation); err != nil {
			return fmt.Errorf("invalid observation: %w", err)
		}
	case FrameCheckpoint:
		if frame.Checkpoint == nil || !validFrameText(frame.Checkpoint.Cursor, protocol.MaxCursorBytes) {
			return errors.New("invalid checkpoint frame")
		}
	case FrameResume:
		if frame.Resume == nil ||
			(frame.Resume.Cursor != "" && !validFrameText(frame.Resume.Cursor, protocol.MaxCursorBytes)) {
			return errors.New("resume frame is missing resume payload")
		}
	case FrameAck:
		if frame.Ack == nil ||
			!validFrameText(frame.Ack.Cursor, protocol.MaxCursorBytes) ||
			(frame.Ack.EventID != "" && !validFrameText(frame.Ack.EventID, protocol.MaxEventIDBytes)) {
			return errors.New("invalid acknowledgement frame")
		}
	case FrameError:
		if frame.Error == nil || frame.Error.Code == "" || frame.Error.Message == "" {
			return errors.New("invalid error frame")
		}
	default:
		return fmt.Errorf("unsupported adapter frame type %q", frame.Type)
	}
	return nil
}

func validFrameText(value string, maxBytes int) bool {
	if value == "" || len(value) > maxBytes || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
