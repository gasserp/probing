package openssh

import (
	"encoding/json"
	"testing"
)

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

func TestParseOpenSSHTakesAddressFromSSHDSuffix(t *testing.T) {
	for _, test := range []struct {
		name     string
		message  string
		username string
		address  string
	}{
		{
			name:     "username embeds a spoofed address",
			message:  "Failed password for invalid user x from 198.51.100.7 port 22 ssh2 from 192.0.2.12 port 4242 ssh2",
			username: "x from 198.51.100.7 port 22 ssh2",
			address:  "192.0.2.12",
		},
		{
			name:     "username with spaces",
			message:  "Failed password for invalid user admin user from 2001:db8::5 port 4242 ssh2",
			username: "admin user",
			address:  "2001:db8::5",
		},
		{
			name:     "publickey fingerprint suffix",
			message:  "Failed publickey for root from 192.0.2.12 port 4242 ssh2: ED25519 SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU",
			username: "root",
			address:  "192.0.2.12",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			line, err := json.Marshal(map[string]string{
				"__CURSOR":             "s=abc;i=124",
				"__REALTIME_TIMESTAMP": "1789066862000000",
				"MESSAGE":              test.message,
			})
			if err != nil {
				t.Fatal(err)
			}
			observation, matched, err := Parse(line)
			if err != nil {
				t.Fatal(err)
			}
			if !matched {
				t.Fatal("failed authentication was ignored")
			}
			if observation.SourceIP != test.address || observation.SSH.Username != test.username {
				t.Fatalf("observation = %+v, ssh = %+v", observation, observation.SSH)
			}
		})
	}
}

func TestParseOpenSSHSkipsUnanchoredMessages(t *testing.T) {
	for _, message := range []string{
		"Failed password for invalid user x from 198.51.100.7 port 22",
		"Failed password for root from 192.0.2.12 port 4242 ssh2 trailing",
		"Failed publickey for root from 192.0.2.12 port 4242 ssh2: ED25519-CERT SHA256:abc ID attacker from 198.51.100.7 (serial 1) CA ED25519 SHA256:def",
	} {
		line, err := json.Marshal(map[string]string{
			"__CURSOR":             "s=abc;i=125",
			"__REALTIME_TIMESTAMP": "1789066862000000",
			"MESSAGE":              message,
		})
		if err != nil {
			t.Fatal(err)
		}
		_, matched, err := Parse(line)
		if err != nil {
			t.Fatal(err)
		}
		if matched {
			t.Fatalf("message %q was counted", message)
		}
	}
}
