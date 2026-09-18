package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gasserp/probing/adapter"
)

const (
	MaxAdapterSocketPathBytes = 4_096
	adapterConnectRetry       = time.Second
)

type AdapterCommand struct {
	ID         string `json:"id"`
	SocketPath string `json:"socket_path"`
}

type Supervisor struct {
	processor *Processor
}

func NewSupervisor(processor *Processor) (*Supervisor, error) {
	if processor == nil {
		return nil, errors.New("processor is required")
	}
	return &Supervisor{processor: processor}, nil
}

func (s *Supervisor) Run(ctx context.Context, commands []AdapterCommand) error {
	if len(commands) == 0 {
		return errors.New("at least one adapter command is required")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan error, len(commands))
	var waitGroup sync.WaitGroup
	for _, command := range commands {
		command := command
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			results <- s.runAdapter(ctx, command)
		}()
	}
	go func() {
		waitGroup.Wait()
		close(results)
	}()

	var firstError error
	for err := range results {
		if err != nil && firstError == nil {
			firstError = err
			cancel()
		}
	}
	return firstError
}

func (s *Supervisor) runAdapter(ctx context.Context, config AdapterCommand) error {
	if config.ID == "" || !validSocketPath(config.SocketPath) {
		return errors.New("adapter ID and absolute socket_path are required")
	}

	connection, err := dialAdapter(ctx, config.SocketPath)
	if err != nil {
		return fmt.Errorf("connect adapter %s: %w", config.ID, err)
	}
	defer connection.Close()
	closed := make(chan struct{})
	defer close(closed)
	go func() {
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-closed:
		}
	}()

	decoder := adapter.NewDecoder(connection, adapter.DefaultMaxFrameBytes)
	hello, err := decoder.Next()
	if err != nil {
		return fmt.Errorf("negotiate adapter %s: %w", config.ID, err)
	}
	if hello.Type != adapter.FrameHello {
		return fmt.Errorf("adapter %s did not send hello", config.ID)
	}
	cursor, found, err := s.processor.store.Cursor(ctx, config.ID)
	if err != nil {
		return fmt.Errorf("load adapter %s cursor: %w", config.ID, err)
	}
	if !found {
		cursor = ""
	}
	if err := adapter.Encode(connection, adapter.Frame{
		Type:   adapter.FrameResume,
		Resume: &adapter.Resume{Cursor: cursor},
	}); err != nil {
		return fmt.Errorf("send adapter %s resume cursor: %w", config.ID, err)
	}

	for {
		frame, err := decoder.Next()
		if errors.Is(err, io.EOF) {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("adapter %s disconnected", config.ID)
		}
		if err != nil {
			return fmt.Errorf("read adapter %s: %w", config.ID, err)
		}

		var eventID, committedCursor string
		switch frame.Type {
		case adapter.FrameObservation:
			if err := s.processor.Process(ctx, config.ID, *frame.Observation); err != nil {
				return fmt.Errorf("process adapter %s observation: %w", config.ID, err)
			}
			eventID = frame.Observation.EventID
			committedCursor = frame.Observation.Cursor
		case adapter.FrameCheckpoint:
			if err := s.processor.Checkpoint(ctx, config.ID, frame.Checkpoint.Cursor); err != nil {
				return fmt.Errorf("process adapter %s checkpoint: %w", config.ID, err)
			}
			committedCursor = frame.Checkpoint.Cursor
		case adapter.FrameError:
			return fmt.Errorf("adapter %s reported %s: %s", config.ID, frame.Error.Code, frame.Error.Message)
		default:
			return fmt.Errorf("adapter %s sent invalid frame type %q", config.ID, frame.Type)
		}
		if err := adapter.Encode(connection, adapter.Frame{
			Type: adapter.FrameAck,
			Ack:  &adapter.Ack{EventID: eventID, Cursor: committedCursor},
		}); err != nil {
			return fmt.Errorf("acknowledge adapter %s: %w", config.ID, err)
		}
	}
}

func dialAdapter(ctx context.Context, socketPath string) (net.Conn, error) {
	dialer := net.Dialer{}
	for {
		connection, err := dialer.DialContext(ctx, "unix", socketPath)
		if err == nil {
			return connection, nil
		}
		timer := time.NewTimer(adapterConnectRetry)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func validSocketPath(path string) bool {
	if path == "" || len(path) > MaxAdapterSocketPathBytes || !utf8.ValidString(path) ||
		!filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	for _, r := range path {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return !strings.Contains(path, "\x00")
}
