package cowrie

import (
	"strings"
	"testing"
)

func TestParseCowrieFailedLogin(t *testing.T) {
	line := []byte(`{
		"eventid":"cowrie.login.failed",
		"timestamp":"2026-09-10T19:01:02.123456Z",
		"src_ip":"2001:db8::5",
		"username":"root",
		"password":"123456",
		"session":"abc"
	}`)
	observation, matched, err := Parse(line, "inode=2;offset=15")
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("Cowrie failed login was ignored")
	}
	if observation.SSH.Username != "root" || observation.SourceIP != "2001:db8::5" {
		t.Fatalf("observation = %#v", observation)
	}
	if observation.SSH.Password != "123456" {
		t.Fatalf("attempted password was not captured: %#v", observation.SSH)
	}
}

func TestParseCowrieDropsUnusablePassword(t *testing.T) {
	oversized := strings.Repeat("a", 300)
	line := []byte(`{
		"eventid":"cowrie.login.failed",
		"timestamp":"2026-09-10T19:01:02Z",
		"src_ip":"192.0.2.5",
		"username":"admin",
		"password":"` + oversized + `"
	}`)
	observation, matched, err := Parse(line, "inode=2;offset=16")
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("Cowrie failed login was ignored")
	}
	if observation.SSH.Username != "admin" {
		t.Fatalf("observation = %#v", observation)
	}
	if observation.SSH.Password != "" {
		t.Fatalf("unusable password should have been dropped: %q", observation.SSH.Password)
	}
}

func TestParseCowrieMissingPassword(t *testing.T) {
	line := []byte(`{
		"eventid":"cowrie.login.failed",
		"timestamp":"2026-09-10T19:01:02Z",
		"src_ip":"192.0.2.9",
		"username":"guest"
	}`)
	observation, matched, err := Parse(line, "inode=2;offset=17")
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("Cowrie failed login was ignored")
	}
	if observation.SSH.Password != "" {
		t.Fatalf("absent password should stay empty: %q", observation.SSH.Password)
	}
}

func TestParseCowrieIgnoresOtherEvents(t *testing.T) {
	line := []byte(`{
		"eventid":"cowrie.session.connect",
		"timestamp":"2026-09-10T19:01:02Z",
		"src_ip":"192.0.2.5"
	}`)
	_, matched, err := Parse(line, "inode=2;offset=14")
	if err != nil {
		t.Fatal(err)
	}
	if matched {
		t.Fatal("non-login Cowrie event was counted")
	}
}
