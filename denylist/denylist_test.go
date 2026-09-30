package denylist

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

func key(value string) netip.Prefix {
	return Key(netip.MustParseAddr(value))
}

func TestKeyNormalizesAddresses(t *testing.T) {
	for input, want := range map[string]string{
		"11.0.0.7":                 "11.0.0.7/32",
		"::ffff:11.0.0.7":          "11.0.0.7/32",
		"2a01:4f8:1:2:aaaa::1":     "2a01:4f8:1:2::/64",
		"2a01:4f8:1:2:ffff:ffff::": "2a01:4f8:1:2::/64",
	} {
		if got := key(input).String(); got != want {
			t.Errorf("Key(%s) = %s, want %s", input, got, want)
		}
	}
}

func TestBuildAppliesWindowsAndEvidence(t *testing.T) {
	state := map[string]Record{}
	// Seen once, 2 hours ago: recent only.
	Observe(state, key("11.0.0.1"), "a", now.Add(-3*time.Hour))
	// Seen once, 4 days ago: neither.
	Observe(state, key("11.0.0.2"), "a", now.Add(-96*time.Hour))
	// Three different days from one source: persistent, not recent.
	for _, days := range []int{10, 5, 4} {
		Observe(state, key("11.0.0.3"), "a", now.AddDate(0, 0, -days))
	}
	// Two days from one source: not persistent.
	for _, days := range []int{5, 4} {
		Observe(state, key("11.0.0.4"), "a", now.AddDate(0, 0, -days))
	}
	// Two sources on the same day: persistent and recent.
	Observe(state, key("11.0.0.5"), "a", now.Add(-time.Hour))
	Observe(state, key("11.0.0.5"), "b", now.Add(-time.Hour))
	// Three days, but the oldest two fell out of the 30-day window.
	for _, days := range []int{40, 35, 4} {
		Observe(state, key("11.0.0.6"), "a", now.AddDate(0, 0, -days))
	}
	// Two sources, but one of them only more than 30 days ago.
	Observe(state, key("11.0.0.7"), "a", now.AddDate(0, 0, -35))
	Observe(state, key("11.0.0.7"), "b", now.AddDate(0, 0, -4))

	recent, persistent := Build(state, nil, now)
	if got := prefixes(recent); got != "11.0.0.1/32 11.0.0.5/32" {
		t.Errorf("recent = %s", got)
	}
	if got := prefixes(persistent); got != "11.0.0.3/32 11.0.0.5/32" {
		t.Errorf("persistent = %s", got)
	}
	// 11.0.0.1 was seen in the hour ending 2 hours ago.
	if want := RecentWindow - 2*time.Hour; recent[0].Timeout != want {
		t.Errorf("recent timeout = %s, want %s", recent[0].Timeout, want)
	}
}

func TestBuildLeavesOutSpecialPurposeAndNeverBlock(t *testing.T) {
	state := map[string]Record{}
	for _, address := range []string{
		"10.1.2.3", "100.64.0.1", "192.0.2.1", "203.0.113.9", "127.0.0.1",
		"fe80::1", "fd00::1", "2001:db8::1", "::1",
		"11.0.0.1", "1.1.1.1", "2a01:4f8:1:2::1", "2a01:4f8:9:9::1",
	} {
		Observe(state, key(address), "a", now.Add(-2*time.Hour))
	}
	never := []netip.Prefix{netip.MustParsePrefix("1.1.1.1/32"), netip.MustParsePrefix("2a01:4f8:9:9::5/128")}
	recent, _ := Build(state, never, now)
	if got := prefixes(recent); got != "11.0.0.1/32 2a01:4f8:1:2::/64" {
		t.Errorf("recent = %s", got)
	}
}

func TestPruneAndCap(t *testing.T) {
	state := map[string]Record{}
	Observe(state, key("11.0.0.1"), "a", now.AddDate(0, 0, -31))
	Observe(state, key("11.0.0.2"), "a", now.AddDate(0, 0, -40))
	Observe(state, key("11.0.0.2"), "b", now.AddDate(0, 0, -1))
	Prune(state, now)
	if _, found := state["11.0.0.1/32"]; found {
		t.Error("record older than 30 days survived")
	}
	record := state["11.0.0.2/32"]
	if len(record.Days) != 1 || len(record.Sources) != 1 || record.Sources["b"] == "" {
		t.Errorf("stale days or sources survived: %#v", record)
	}

	Observe(state, key("11.0.0.3"), "a", now.Add(-5*time.Hour))
	Observe(state, key("11.0.0.4"), "a", now.Add(-1*time.Hour))
	Cap(state, 2)
	if len(state) != 2 || state["11.0.0.2/32"].LastSeen != "" {
		t.Errorf("cap did not evict the oldest record: %#v", state)
	}
	if err := Validate(state); err != nil {
		t.Fatal(err)
	}
}

func TestCloneIsDeep(t *testing.T) {
	state := map[string]Record{}
	Observe(state, key("11.0.0.1"), "a", now)
	clone := Clone(state)
	Observe(clone, key("11.0.0.1"), "b", now.AddDate(0, 0, 1))
	if len(state["11.0.0.1/32"].Sources) != 1 || len(state["11.0.0.1/32"].Days) != 1 {
		t.Errorf("clone shares state with the original: %#v", state)
	}
}

func TestValidateRejectsNonCanonicalKeys(t *testing.T) {
	record := Record{LastSeen: "2026-09-30T12:00:00Z", Days: []string{"2026-09-30"}, Sources: map[string]string{"a": "2026-09-30"}}
	for _, bad := range []string{"11.0.0.1", "2a01:4f8:1:2::1/64", "2a01:4f8:1:2::/48", "::ffff:11.0.0.1/128"} {
		if err := Validate(map[string]Record{bad: record}); err == nil {
			t.Errorf("Validate accepted key %q", bad)
		}
	}
}

func TestLoadNeverBlock(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "never-block.json")
	if prefixes, err := LoadNeverBlock(path); err != nil || prefixes != nil {
		t.Fatalf("missing file: %v %v", prefixes, err)
	}
	write := func(content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"schema_version":"probing.never-block/v1","entries":[{"cidr":"1.1.1.0/24","reason":"resolver"},{"cidr":"::ffff:8.8.8.8/128","reason":"resolver"}]}`)
	prefixes, err := LoadNeverBlock(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(prefixes) != 2 || prefixes[1].String() != "8.8.8.8/32" {
		t.Fatalf("prefixes = %v", prefixes)
	}
	for _, bad := range []string{
		`{"schema_version":"probing.never-block/v1","entries":[{"cidr":"1.1.1.1","reason":"x"}]}`,
		`{"schema_version":"probing.never-block/v1","entries":[{"cidr":"1.1.1.1/32","reason":""}]}`,
		`{"schema_version":"probing.never-block/v1","entries":[],"extra":1}`,
		`{"schema_version":"other","entries":[]}`,
	} {
		write(bad)
		if _, err := LoadNeverBlock(path); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestRenderedFormats(t *testing.T) {
	entries := []Entry{
		{netip.MustParsePrefix("11.0.0.1/32"), 90 * time.Second},
		{netip.MustParsePrefix("11.0.0.2/32"), PersistentWindow},
		{netip.MustParsePrefix("2a01:4f8:1:2::/64"), time.Hour},
	}
	head := "# probing deny list: persistent\n# self-reported suspected probes\n# generated 2026-09-30T12:00:00Z\n# " + documentation + "\n"

	if got, want := string(Text("persistent", entries, now)), head+"11.0.0.1\n11.0.0.2\n2a01:4f8:1:2::/64\n"; got != want {
		t.Errorf("text:\n%s\nwant:\n%s", got, want)
	}

	wantNFT := head + `table inet probing {
	set persistent_v4 { type ipv4_addr; flags timeout; }
	set persistent_v6 { type ipv6_addr; flags interval, timeout; }
}
flush set inet probing persistent_v4
flush set inet probing persistent_v6
add element inet probing persistent_v4 {
	11.0.0.1 timeout 90s,
	11.0.0.2 timeout 2592000s
}
add element inet probing persistent_v6 {
	2a01:4f8:1:2::/64 timeout 3600s
}
`
	if got := string(NFT("persistent", entries, now)); got != wantNFT {
		t.Errorf("nft:\n%s\nwant:\n%s", got, wantNFT)
	}
	if got := string(NFT("recent", nil, now)); strings.Contains(got, "add element") {
		t.Errorf("empty nft list must not add elements:\n%s", got)
	}

	wantIPSet := head + `create probing-persistent-v4 hash:ip family inet timeout 2147483
create probing-persistent-v4-new hash:ip family inet timeout 2147483
flush probing-persistent-v4-new
add probing-persistent-v4-new 11.0.0.1 timeout 90
add probing-persistent-v4-new 11.0.0.2 timeout 2147483
swap probing-persistent-v4-new probing-persistent-v4
destroy probing-persistent-v4-new
create probing-persistent-v6 hash:net family inet6 timeout 2147483
create probing-persistent-v6-new hash:net family inet6 timeout 2147483
flush probing-persistent-v6-new
add probing-persistent-v6-new 2a01:4f8:1:2::/64 timeout 3600
swap probing-persistent-v6-new probing-persistent-v6
destroy probing-persistent-v6-new
`
	if got := string(IPSet("persistent", entries, PersistentWindow, now)); got != wantIPSet {
		t.Errorf("ipset:\n%s\nwant:\n%s", got, wantIPSet)
	}
}

func prefixes(entries []Entry) string {
	values := make([]string, len(entries))
	for i, entry := range entries {
		values[i] = entry.Prefix.String()
	}
	return strings.Join(values, " ")
}
