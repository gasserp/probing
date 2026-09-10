package openssh

import "testing"

func TestParseOpenSSHFailedPassword(t *testing.T) {
	line := []byte(`{
		"__CURSOR":"s=abc;i=123",
		"__REALTIME_TIMESTAMP":"1789066862000000",
		"MESSAGE":"Failed password for invalid user admin from ::ffff:192.0.2.12 port 4242 ssh2",
		"_SYSTEMD_UNIT":"ssh.service"
	}`)
	observation, matched, err := Parse(line)
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("failed authentication was ignored")
	}
	if observation.SourceIP != "192.0.2.12" || observation.SSH.Username != "admin" {
		t.Fatalf("observation = %#v", observation)
	}
	if observation.ObservedAt != "2026-09-10T19:01:02Z" {
		t.Fatalf("observation time = %q", observation.ObservedAt)
	}
}

func TestParseOpenSSHIgnoresOverlappingInvalidUserMessage(t *testing.T) {
	line := []byte(`{
		"__CURSOR":"s=abc;i=122",
		"__REALTIME_TIMESTAMP":"1789066861000000",
		"MESSAGE":"Invalid user admin from 192.0.2.12 port 4242"
	}`)
	_, matched, err := Parse(line)
	if err != nil {
		t.Fatal(err)
	}
	if matched {
		t.Fatal("overlapping Invalid user message was counted")
	}
}
