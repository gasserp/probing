package core

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/gasserp/probing/adapter"
)

const MaxDiagnosticLineBytes = 8 * 1024

type AdapterCommand struct {
	ID      string   `json:"id"`
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
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
	if config.ID == "" || config.Command == "" {
		return errors.New("adapter ID and command are required")
	}
	command := exec.CommandContext(ctx, config.Command, config.Args...)
	command.Env = []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
		"TZ=UTC",
	}
	command.WaitDelay = 5 * time.Second
	configureAdapterCommand(command)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return fmt.Errorf("open %s stdout: %w", config.ID, err)
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		return fmt.Errorf("open %s stdin: %w", config.ID, err)
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		return fmt.Errorf("open %s stderr: %w", config.ID, err)
	}
	if err := command.Start(); err != nil {
		return fmt.Errorf("start adapter %s: %w", config.ID, err)
	}
	defer func() {
		_ = stdin.Close()
		if command.ProcessState == nil {
			_ = terminateAdapterProcess(command)
			_ = command.Wait()
		}
	}()
	go logDiagnostics(config.ID, stderr)

	decoder := adapter.NewDecoder(stdout, adapter.DefaultMaxFrameBytes)
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
	if err := adapter.Encode(stdin, adapter.Frame{
		Type:   adapter.FrameResume,
		Resume: &adapter.Resume{Cursor: cursor},
	}); err != nil {
		return fmt.Errorf("send adapter %s resume cursor: %w", config.ID, err)
	}

	for {
		frame, err := decoder.Next()
		if errors.Is(err, io.EOF) {
			if waitErr := command.Wait(); waitErr != nil {
				return fmt.Errorf("adapter %s exited: %w", config.ID, waitErr)
			}
			return nil
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
		if err := adapter.Encode(stdin, adapter.Frame{
			Type: adapter.FrameAck,
			Ack:  &adapter.Ack{EventID: eventID, Cursor: committedCursor},
		}); err != nil {
			return fmt.Errorf("acknowledge adapter %s: %w", config.ID, err)
		}
	}
}

func logDiagnostics(adapterID string, reader io.Reader) {
	buffered := bufio.NewReaderSize(reader, MaxDiagnosticLineBytes)
	for {
		line, prefix, err := buffered.ReadLine()
		if len(line) > 0 {
			if prefix {
				log.Printf("adapter %s: %q [truncated]", adapterID, line)
			} else {
				log.Printf("adapter %s: %q", adapterID, line)
			}
		}
		for prefix {
			_, prefix, err = buffered.ReadLine()
			if err != nil {
				break
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrClosed) {
				log.Printf("adapter %s diagnostics stopped: %q", adapterID, err.Error())
			}
			return
		}
	}
}
