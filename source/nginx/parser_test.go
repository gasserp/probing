package nginx

import "testing"

func TestParseNginxJSON(t *testing.T) {
	observation, err := Parse(
		[]byte(`{"time":"2026-09-10T21:01:02+02:00","remote_addr":"2001:0db8::1","request_uri":"/%252e%252e%252fetc/passwd?ignored=true","status":404}`),
		"inode=1;offset=10",
	)
	if err != nil {
		t.Fatal(err)
	}
	if observation.SourceIP != "2001:db8::1" {
		t.Fatalf("source IP = %q", observation.SourceIP)
	}
	if observation.ObservedAt != "2026-09-10T19:01:02Z" {
		t.Fatalf("observation time = %q", observation.ObservedAt)
	}
	if observation.HTTP.RequestTarget != "/%252e%252e%252fetc/passwd?ignored=true" {
		t.Fatalf("request target = %q", observation.HTTP.RequestTarget)
	}
}

func TestParseNginxRejectsUnexpectedFields(t *testing.T) {
	_, err := Parse(
		[]byte(`{"time":"2026-09-10T19:01:02Z","remote_addr":"192.0.2.1","request_uri":"/","status":404,"request_body":"secret"}`),
		"inode=1;offset=11",
	)
	if err == nil {
		t.Fatal("Nginx parser accepted an unexpected field")
	}
}
