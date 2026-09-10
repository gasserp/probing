package source

import (
	"bytes"
	"strings"
	"testing"
)

func TestDecodeJSONBoundsAndStrictness(t *testing.T) {
	var value struct {
		Name string `json:"name"`
	}
	if err := DecodeJSON([]byte(`{"name":"sensor"}`), &value, true); err != nil {
		t.Fatal(err)
	}
	if err := DecodeJSON([]byte(`{"name":"sensor","extra":true}`), &value, true); err == nil {
		t.Fatal("strict decoder accepted an unknown property")
	}
	if err := DecodeJSON([]byte("{\"name\":\"\xff\"}"), &value, true); err == nil {
		t.Fatal("decoder accepted invalid UTF-8")
	}
	if err := DecodeJSON(bytes.Repeat([]byte("x"), MaxLogLineBytes+1), &value, true); err == nil {
		t.Fatal("decoder accepted an oversized line")
	}
}

func TestEventIDIsStableAndDoesNotExposeCursor(t *testing.T) {
	first, err := EventID("nginx", "inode=12;offset=400")
	if err != nil {
		t.Fatal(err)
	}
	second, err := EventID("nginx", "inode=12;offset=400")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("event ID is not stable")
	}
	if strings.Contains(first, "offset") {
		t.Fatal("event ID exposed its source cursor")
	}
}

func TestCanonicalIPUnmapsIPv4(t *testing.T) {
	got, err := CanonicalIP("::ffff:192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if got != "192.0.2.1" {
		t.Fatalf("CanonicalIP() = %q", got)
	}
}
