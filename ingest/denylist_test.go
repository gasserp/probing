package ingest

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gasserp/probing/protocol"
)

func denyListRecord(kind protocol.ObservationKind, ip, username, path string) protocol.BatchRecord {
	return protocol.BatchRecord{
		Kind:            kind,
		SourceIP:        ip,
		Username:        username,
		Path:            path,
		Count:           1,
		FirstObservedAt: "2026-09-30T09:10:00Z",
		LastObservedAt:  "2026-09-30T09:10:00Z",
		HourlyBuckets:   []protocol.HourlyBucket{{Hour: "2026-09-30T09:00:00Z", Count: 1}},
	}
}

func TestApplyDenyListQualifyingEvents(t *testing.T) {
	payload := protocol.BatchPayload{
		SourceID: "sensor-one",
		Records: []protocol.BatchRecord{
			// One username, many failures: never qualifies on a host.
			denyListRecord(protocol.ObservationSSHAuthFailure, "11.0.0.1", "root", ""),
			// Two usernames in the same hour.
			denyListRecord(protocol.ObservationSSHAuthFailure, "11.0.0.2", "root", ""),
			denyListRecord(protocol.ObservationSSHAuthFailure, "11.0.0.2", "admin", ""),
			// An HTTP rule match always qualifies.
			denyListRecord(protocol.ObservationHTTPRequest, "11.0.0.3", "", "/.env"),
			// Two addresses in the same /64 with one username each add up.
			denyListRecord(protocol.ObservationSSHAuthFailure, "2a01:4f8:1:2::1", "root", ""),
			denyListRecord(protocol.ObservationSSHAuthFailure, "2a01:4f8:1:2::2", "pi", ""),
		},
	}
	payload.Records[0].Count = 50

	host := Ledger{}
	if err := applyDenyList(&host, payload, SourceKindHost); err != nil {
		t.Fatal(err)
	}
	if got := keys(host); got != "11.0.0.2/32 11.0.0.3/32 2a01:4f8:1:2::/64" {
		t.Errorf("host deny list = %s", got)
	}
	record := host.DenyList["11.0.0.2/32"]
	if record.LastSeen != "2026-09-30T10:00:00Z" || record.Sources["sensor-one"] != "2026-09-30" {
		t.Errorf("record = %#v", record)
	}

	decoy := Ledger{}
	if err := applyDenyList(&decoy, payload, SourceKindDecoy); err != nil {
		t.Fatal(err)
	}
	if got := keys(decoy); got != "11.0.0.1/32 11.0.0.2/32 11.0.0.3/32 2a01:4f8:1:2::/64" {
		t.Errorf("decoy deny list = %s", got)
	}
}

func TestWriteDenyListsFromLedger(t *testing.T) {
	repository := t.TempDir()
	ledger := Ledger{
		SchemaVersion: LedgerSchemaVersion,
		Repository:    "gasserp/probing-data",
		Sources:       []LedgerSource{},
		Periods:       map[string]PeriodLedger{},
	}
	payload := protocol.BatchPayload{
		SourceID: "sensor-one",
		Records: []protocol.BatchRecord{
			denyListRecord(protocol.ObservationHTTPRequest, "11.0.0.3", "", "/.env"),
			denyListRecord(protocol.ObservationHTTPRequest, "1.1.1.1", "", "/.env"),
		},
	}
	if err := applyDenyList(&ledger, payload, SourceKindDecoy); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repository, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repository, "registry"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := atomicJSON(filepath.Join(repository, "data", "acceptance-ledger.json"), ledger, 0o644); err != nil {
		t.Fatal(err)
	}
	never := `{"schema_version":"probing.never-block/v1","entries":[{"cidr":"1.1.1.1/32","reason":"resolver"}]}`
	if err := os.WriteFile(filepath.Join(repository, "registry", "never-block.json"), []byte(never), 0o644); err != nil {
		t.Fatal(err)
	}

	output := filepath.Join(t.TempDir(), "deny-list")
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	if err := WriteDenyLists(repository, "gasserp/probing-data", output, now); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"recent", "persistent"} {
		for _, extension := range []string{".txt", ".nft", ".ipset"} {
			if _, err := os.Stat(filepath.Join(output, name+extension)); err != nil {
				t.Error(err)
			}
		}
	}
	recent, err := os.ReadFile(filepath.Join(output, "recent.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(recent), "\n11.0.0.3\n") || strings.Contains(string(recent), "1.1.1.1") {
		t.Errorf("recent.txt:\n%s", recent)
	}
	persistent, err := os.ReadFile(filepath.Join(output, "persistent.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(persistent), "11.0.0.3") {
		t.Errorf("one event on one day must not be persistent:\n%s", persistent)
	}
}

func keys(ledger Ledger) string {
	values := make([]string, 0, len(ledger.DenyList))
	for key := range ledger.DenyList {
		values = append(values, key)
	}
	sort.Strings(values)
	return strings.Join(values, " ")
}
