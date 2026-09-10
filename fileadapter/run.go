package fileadapter

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/gasserp/probing/adapter"
	"github.com/gasserp/probing/protocol"
	"github.com/gasserp/probing/source"
)

type Parser func(line []byte, cursor string) (protocol.Observation, bool, error)

type Config struct {
	Name         string
	Version      string
	Path         string
	Once         bool
	PollInterval time.Duration
}

func Run(ctx context.Context, config Config, parser Parser, control io.Reader, output io.Writer) error {
	if config.Name == "" || config.Version == "" || config.Path == "" || parser == nil {
		return errors.New("adapter name, version, path, and parser are required")
	}
	if config.PollInterval <= 0 {
		config.PollInterval = time.Second
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

	file, identity, offset, err := openAtCursor(config.Path, resume.Resume.Cursor)
	if err != nil {
		return err
	}
	defer file.Close()
	reader := bufio.NewReaderSize(file, 4096)
	var partial []byte

	for {
		fragment, readErr := reader.ReadSlice('\n')
		if len(partial)+len(fragment) > source.MaxLogLineBytes {
			return fmt.Errorf("log line exceeds %d bytes", source.MaxLogLineBytes)
		}
		partial = append(partial, fragment...)
		offset += int64(len(fragment))

		if readErr == nil {
			line := strings.TrimSuffix(strings.TrimSuffix(string(partial), "\n"), "\r")
			cursor := identity.cursor(offset)
			if err := emitLine([]byte(line), cursor, parser, controlDecoder, output); err != nil {
				return err
			}
			partial = partial[:0]
			continue
		}
		if errors.Is(readErr, bufio.ErrBufferFull) {
			continue
		}
		if !errors.Is(readErr, io.EOF) {
			return fmt.Errorf("read log file: %w", readErr)
		}
		if config.Once {
			if len(partial) != 0 {
				return errors.New("log file ends with an incomplete line")
			}
			return nil
		}
		if err := waitForChange(ctx, config.PollInterval); err != nil {
			return err
		}
		info, err := os.Stat(config.Path)
		if err != nil {
			return fmt.Errorf("stat log path: %w", err)
		}
		if !os.SameFile(info, identity.info) || info.Size() < offset {
			if len(partial) != 0 {
				return errors.New("log rotated or truncated with an incomplete line")
			}
			if err := file.Close(); err != nil {
				return err
			}
			file, identity, offset, err = openAtCursor(config.Path, "")
			if err != nil {
				return err
			}
			reader.Reset(file)
		}
	}
}

func emitLine(
	line []byte,
	cursor string,
	parser Parser,
	control *adapter.ControlDecoder,
	output io.Writer,
) error {
	observation, matched, err := parser(line, cursor)
	if err != nil {
		return err
	}
	frame := adapter.Frame{Type: adapter.FrameCheckpoint, Checkpoint: &adapter.Checkpoint{Cursor: cursor}}
	eventID := ""
	if matched {
		frame = adapter.Frame{Type: adapter.FrameObservation, Observation: &observation}
		eventID = observation.EventID
	}
	if err := adapter.Encode(output, frame); err != nil {
		return err
	}
	ack, err := control.Next()
	if err != nil {
		return fmt.Errorf("read acknowledgement: %w", err)
	}
	if ack.Type == adapter.FrameError {
		return fmt.Errorf("core rejected input with %s: %s", ack.Error.Code, ack.Error.Message)
	}
	if ack.Type != adapter.FrameAck || ack.Ack.Cursor != cursor || ack.Ack.EventID != eventID {
		return errors.New("core acknowledgement does not match emitted input")
	}
	return nil
}

type fileIdentity struct {
	info   os.FileInfo
	device uint64
	inode  uint64
}

func openAtCursor(path, resume string) (*os.File, fileIdentity, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fileIdentity{}, 0, fmt.Errorf("open log file: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fileIdentity{}, 0, fmt.Errorf("stat log file: %w", err)
	}
	device, inode, err := fileNumbers(info)
	if err != nil {
		file.Close()
		return nil, fileIdentity{}, 0, err
	}
	identity := fileIdentity{info: info, device: device, inode: inode}
	var offset int64
	if resume != "" {
		resumeDevice, resumeInode, resumeOffset, err := parseCursor(resume)
		if err != nil {
			file.Close()
			return nil, fileIdentity{}, 0, err
		}
		if resumeDevice == device && resumeInode == inode && resumeOffset <= info.Size() {
			offset = resumeOffset
		}
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		file.Close()
		return nil, fileIdentity{}, 0, fmt.Errorf("seek log file: %w", err)
	}
	return file, identity, offset, nil
}

func fileNumbers(info os.FileInfo) (uint64, uint64, error) {
	value := reflect.ValueOf(info.Sys())
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if !value.IsValid() {
		return 0, 0, errors.New("file identity is unavailable")
	}
	device := value.FieldByName("Dev")
	inode := value.FieldByName("Ino")
	deviceNumber, ok := fieldUint(device)
	if !ok {
		return 0, 0, errors.New("platform does not expose device file identity")
	}
	inodeNumber, ok := fieldUint(inode)
	if !ok {
		return 0, 0, errors.New("platform does not expose device and inode file identity")
	}
	return deviceNumber, inodeNumber, nil
}

func fieldUint(value reflect.Value) (uint64, bool) {
	if !value.IsValid() {
		return 0, false
	}
	switch value.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return value.Uint(), true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		number := value.Int()
		if number < 0 {
			return 0, false
		}
		return uint64(number), true
	default:
		return 0, false
	}
}

func (identity fileIdentity) cursor(offset int64) string {
	return fmt.Sprintf("file-v1:%x:%x:%d", identity.device, identity.inode, offset)
}

func parseCursor(cursor string) (uint64, uint64, int64, error) {
	parts := strings.Split(cursor, ":")
	if len(parts) != 4 || parts[0] != "file-v1" {
		return 0, 0, 0, errors.New("file cursor is invalid")
	}
	device, err := strconv.ParseUint(parts[1], 16, 64)
	if err != nil {
		return 0, 0, 0, errors.New("file cursor device is invalid")
	}
	inode, err := strconv.ParseUint(parts[2], 16, 64)
	if err != nil {
		return 0, 0, 0, errors.New("file cursor inode is invalid")
	}
	offset, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || offset < 0 {
		return 0, 0, 0, errors.New("file cursor offset is invalid")
	}
	return device, inode, offset, nil
}

func waitForChange(ctx context.Context, interval time.Duration) error {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
