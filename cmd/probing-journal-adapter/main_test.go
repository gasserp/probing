package main

import (
	"slices"
	"testing"
)

func TestJournalctlArgs(t *testing.T) {
	for _, test := range []struct {
		name   string
		cursor string
		follow bool
		want   []string
	}{
		{name: "fresh follow starts at the end", follow: true, want: []string{"--follow", "--lines=0"}},
		{name: "resume drain", cursor: "s=ab;i=1", want: []string{"--no-tail", "--after-cursor=s=ab;i=1"}},
		{name: "resume follow", cursor: "s=ab;i=1", follow: true, want: []string{"--follow", "--no-tail", "--after-cursor=s=ab;i=1"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := journalctlArgs("/journal", "ssh.service", test.cursor, test.follow)
			want := append([]string{
				"--directory=/journal", "--output=json", "--output-fields=MESSAGE", "--no-pager", "--quiet",
			}, test.want...)
			want = append(want, "_SYSTEMD_UNIT=ssh.service")
			if !slices.Equal(args, want) {
				t.Fatalf("args = %q, want %q", args, want)
			}
		})
	}
}

func TestUnitPattern(t *testing.T) {
	for _, unit := range []string{"ssh.service", "sshd.service", "ssh@0-192.0.2.1:22-198.51.100.1:5555.service"} {
		if !unitPattern.MatchString(unit) {
			t.Fatalf("unit %q rejected", unit)
		}
	}
	for _, unit := range []string{"", "ssh", "ssh.socket", "ssh.service --since=today", "-ssh.service\n"} {
		if unitPattern.MatchString(unit) {
			t.Fatalf("unit %q accepted", unit)
		}
	}
}
