package core

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gasserp/probing/adapter"
	"github.com/gasserp/probing/classifier"
	"github.com/gasserp/probing/protocol"
	"github.com/gasserp/probing/store"
)

func TestSupervisorPreservesResumeAndAckOverUnixSocket(t *testing.T) {
	ctx := context.Background()
	state, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	if err := state.CommitCursor(ctx, "nginx", "prior-cursor"); err != nil {
		t.Fatal(err)
	}
	ssh, err := classifier.NewSSHClassifier(classifier.DefaultSSHConfig())
	if err != nil {
		t.Fatal(err)
	}
	http, err := classifier.NewHTTPClassifier(classifier.DefaultHTTPConfig())
	if err != nil {
		t.Fatal(err)
	}
	processor, err := NewProcessor(state, ssh, http)
	if err != nil {
		t.Fatal(err)
	}
	supervisor, err := NewSupervisor(processor)
	if err != nil {
		t.Fatal(err)
	}

	socketDirectory, err := os.MkdirTemp("/tmp", "probing-socket-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(socketDirectory)
	socketPath := filepath.Join(socketDirectory, "adapter.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverResult := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		defer connection.Close()
		if err := adapter.Encode(connection, adapter.Frame{
			Type: adapter.FrameHello,
			Hello: &adapter.Hello{
				ProtocolVersions: []string{protocol.AdapterProtocolVersion},
				AdapterName:      "nginx",
				AdapterVersion:   "test",
			},
		}); err != nil {
			serverResult <- err
			return
		}
		control := adapter.NewControlDecoder(connection, adapter.DefaultMaxFrameBytes)
		resume, err := control.Next()
		if err != nil {
			serverResult <- err
			return
		}
		if resume.Resume.Cursor != "prior-cursor" {
			serverResult <- errors.New("collector sent the wrong durable resume cursor")
			return
		}
		if err := adapter.Encode(connection, adapter.Frame{
			Type:       adapter.FrameCheckpoint,
			Checkpoint: &adapter.Checkpoint{Cursor: "next-cursor"},
		}); err != nil {
			serverResult <- err
			return
		}
		ack, err := control.Next()
		if err != nil {
			serverResult <- err
			return
		}
		if ack.Ack.Cursor != "next-cursor" || ack.Ack.EventID != "" {
			serverResult <- errors.New("collector acknowledgement did not match the checkpoint")
			return
		}
		serverResult <- nil
	}()

	err = supervisor.runAdapter(ctx, AdapterCommand{ID: "nginx", SocketPath: socketPath})
	if err == nil || !strings.Contains(err.Error(), "disconnected") {
		t.Fatalf("runAdapter() error = %v", err)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
	cursor, found, err := state.Cursor(ctx, "nginx")
	if err != nil || !found || cursor != "next-cursor" {
		t.Fatalf("durable cursor = %q, found %v, error %v", cursor, found, err)
	}
}
