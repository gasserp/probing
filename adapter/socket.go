package adapter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
)

const maxSessionDiagnosticBytes = 8 * 1024

// ServeSocket listens on a Unix socket that only the collector's group can
// reach and serves one collector session at a time. A failed session is
// reported to diagnostics, truncated, and the next connection is accepted.
func ServeSocket(ctx context.Context, path string, diagnostics io.Writer, serve func(net.Conn) error) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || serve == nil {
		return errors.New("absolute clean socket path and handler are required")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("adapter socket path exists and is not a socket")
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove stale adapter socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect adapter socket: %w", err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("listen on adapter socket: %w", err)
	}
	defer listener.Close()
	defer os.Remove(path)
	if err := os.Chmod(path, 0o660); err != nil {
		return fmt.Errorf("set adapter socket mode: %w", err)
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept collector connection: %w", err)
		}
		sessionErr := serve(connection)
		_ = connection.Close()
		if sessionErr != nil && ctx.Err() == nil {
			message := sessionErr.Error()
			if len(message) > maxSessionDiagnosticBytes {
				message = message[:maxSessionDiagnosticBytes]
			}
			fmt.Fprintf(diagnostics, "adapter session stopped: %q\n", message)
		}
	}
}
