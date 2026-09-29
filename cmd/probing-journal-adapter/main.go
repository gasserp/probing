package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"syscall"

	"github.com/gasserp/probing/adapter"
	"github.com/gasserp/probing/journaladapter"
	"github.com/gasserp/probing/source/openssh"
)

const version = "0.1.0"

var unitPattern = regexp.MustCompile(`^[A-Za-z0-9:_.@-]{1,255}\.service$`)

func main() {
	directory := flag.String("directory", "/journal", "journal directory, as mounted from the host's /var/log/journal")
	unit := flag.String("unit", "ssh.service", "systemd unit whose records are read")
	journalctl := flag.String("journalctl", "/usr/bin/journalctl", "journalctl binary")
	socketPath := flag.String("socket", "", "Unix socket path for collector IPC")
	flag.Parse()

	if !filepath.IsAbs(*directory) || !unitPattern.MatchString(*unit) || !filepath.IsAbs(*journalctl) {
		fmt.Fprintln(os.Stderr, "usage: probing-journal-adapter -socket <path> [-directory <abs path>] [-unit <name>.service]")
		os.Exit(2)
	}
	if *socketPath == "" {
		fmt.Fprintln(os.Stderr, "-socket is required")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	config := journaladapter.Config{Name: "openssh", Version: version, Diagnostics: os.Stderr}
	source := journalctlSource(*journalctl, *directory, *unit, os.Stderr)
	err := adapter.ServeSocket(ctx, *socketPath, os.Stderr, func(connection net.Conn) error {
		return journaladapter.Run(ctx, config, source, openssh.Parse, connection, connection)
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// journalctlArgs selects only records whose trusted _SYSTEMD_UNIT field,
// which journald sets itself, names the sshd unit. Any local process can
// claim SYSLOG_IDENTIFIER=sshd; none can claim another unit's cgroup.
func journalctlArgs(directory, unit, cursor string, follow bool) []string {
	args := []string{
		"--directory=" + directory,
		"--output=json",
		"--output-fields=MESSAGE",
		"--no-pager",
		"--quiet",
	}
	if follow {
		args = append(args, "--follow")
	}
	if cursor == "" {
		args = append(args, "--lines=0")
	} else {
		args = append(args, "--no-tail", "--after-cursor="+cursor)
	}
	return append(args, "_SYSTEMD_UNIT="+unit)
}

func journalctlSource(binary, directory, unit string, diagnostics io.Writer) journaladapter.Source {
	return func(ctx context.Context, cursor string, follow bool) (io.ReadCloser, error) {
		if cursor != "" && !journaladapter.ValidCursor(cursor) {
			return nil, errors.New("journal cursor is invalid")
		}
		command := exec.CommandContext(ctx, binary, journalctlArgs(directory, unit, cursor, follow)...)
		command.Env = []string{"LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER="}
		command.Stderr = diagnostics
		stdout, err := command.StdoutPipe()
		if err != nil {
			return nil, err
		}
		if err := command.Start(); err != nil {
			return nil, fmt.Errorf("start journalctl: %w", err)
		}
		return &journalctlProcess{ReadCloser: stdout, command: command}, nil
	}
}

type journalctlProcess struct {
	io.ReadCloser
	command *exec.Cmd
	waited  bool
}

// Read reports a journalctl failure, such as a cursor it cannot seek to, as
// an error instead of letting it look like the end of the journal.
func (p *journalctlProcess) Read(buffer []byte) (int, error) {
	n, err := p.ReadCloser.Read(buffer)
	if errors.Is(err, io.EOF) && !p.waited {
		p.waited = true
		if waitErr := p.command.Wait(); waitErr != nil {
			return n, fmt.Errorf("journalctl failed: %w", waitErr)
		}
	}
	return n, err
}

// Close stops journalctl. A drain that already reached the end has exited on
// its own; a follow never does, so it is killed.
func (p *journalctlProcess) Close() error {
	if !p.waited {
		p.waited = true
		_ = p.command.Process.Kill()
		_ = p.command.Wait()
	}
	return nil
}
