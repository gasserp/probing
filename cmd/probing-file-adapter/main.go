package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gasserp/probing/fileadapter"
	"github.com/gasserp/probing/protocol"
	"github.com/gasserp/probing/source/cowrie"
	"github.com/gasserp/probing/source/nginx"
)

const version = "0.1.0"

func main() {
	format := flag.String("format", "", "log format: nginx or cowrie")
	path := flag.String("file", "", "path to the JSON-lines log file")
	socketPath := flag.String("socket", "", "Unix socket path for collector IPC")
	once := flag.Bool("once", false, "read current complete lines and exit")
	poll := flag.Duration("poll", time.Second, "poll interval while following")
	flag.Parse()

	parser, err := selectParser(*format)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	config := fileadapter.Config{
		Name:         *format,
		Version:      version,
		Path:         *path,
		Once:         *once,
		PollInterval: *poll,
	}
	if *socketPath == "" {
		err = errors.New("-socket is required")
	} else {
		err = serveSocket(ctx, *socketPath, func(connection net.Conn) error {
			return fileadapter.Run(ctx, config, parser, connection, connection)
		})
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serveSocket(ctx context.Context, path string, serve func(net.Conn) error) error {
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
			fmt.Fprintf(os.Stderr, "adapter session stopped: %q\n", sessionErr.Error())
		}
	}
}

func selectParser(format string) (fileadapter.Parser, error) {
	switch format {
	case "nginx":
		return recoverInvalidRecords(format, func(line []byte, cursor string) (protocol.Observation, bool, error) {
			observation, err := nginx.Parse(line, cursor)
			return observation, err == nil, err
		}, os.Stderr), nil
	case "cowrie":
		return recoverInvalidRecords(format, cowrie.Parse, os.Stderr), nil
	default:
		return nil, fmt.Errorf("unsupported format %q", format)
	}
}

func recoverInvalidRecords(format string, parser fileadapter.Parser, diagnostics io.Writer) fileadapter.Parser {
	return func(line []byte, cursor string) (protocol.Observation, bool, error) {
		observation, matched, err := parser(line, cursor)
		if err == nil {
			return observation, matched, nil
		}
		fmt.Fprintf(diagnostics, "ignored invalid %s record: %q\n", format, err.Error())
		return protocol.Observation{}, false, nil
	}
}
