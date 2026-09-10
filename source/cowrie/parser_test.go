package cowrie

import "testing"

func TestParseCowrieFailedLogin(t *testing.T) {
	line := []byte(`{
		"eventid":"cowrie.login.failed",
		"timestamp":"2026-09-10T19:01:02.123456Z",
		"src_ip":"2001:db8::5",
		"username":"root",
		"password":"must-not-be-copied",
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
