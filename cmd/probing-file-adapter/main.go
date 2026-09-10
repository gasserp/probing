package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
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
	err = fileadapter.Run(ctx, fileadapter.Config{
		Name:         *format,
		Version:      version,
		Path:         *path,
		Once:         *once,
		PollInterval: *poll,
	}, parser, os.Stdin, os.Stdout)
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func selectParser(format string) (fileadapter.Parser, error) {
	switch format {
	case "nginx":
		return func(line []byte, cursor string) (protocol.Observation, bool, error) {
			observation, err := nginx.Parse(line, cursor)
			return observation, err == nil, err
		}, nil
	case "cowrie":
		return cowrie.Parse, nil
	default:
		return nil, fmt.Errorf("unsupported format %q", format)
	}
}
