package ingest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gasserp/probing/protocol"
	"github.com/gasserp/probing/publication"
)

const rulesTestHour = "2026-09-10T19:00:00Z"

func httpRecord(ip, path string, buckets []protocol.HourlyBucket, rules ...string) protocol.BatchRecord {
	var count uint64
	for _, bucket := range buckets {
		count += bucket.Count
	}
	return protocol.BatchRecord{
		Kind:            protocol.ObservationHTTPRequest,
		SourceIP:        ip,
		Path:            path,
		Count:           count,
		FirstObservedAt: buckets[0].Hour,
		LastObservedAt:  buckets[len(buckets)-1].Hour,
		HourlyBuckets:   buckets,
		RuleIDs:         rules,
	}
}

func rulesPayload(records ...protocol.BatchRecord) protocol.BatchPayload {
	return protocol.BatchPayload{
		SchemaVersion:     protocol.BatchSchemaVersion,
		SourceID:          "sensor-one",
		SourceEpoch:       "5d6079de-20e0-4d4b-b955-40eac8f14df8",
		Sequence:          "0",
		CreatedAt:         "2026-09-10T21:00:00Z",
		ObservationWindow: protocol.TimeRange{Start: rulesTestHour, End: "2026-09-10T21:00:00Z"},
		ClassifierVersion: "classifier-v1",
		Records:           records,
	}
}

func emptyLedger() Ledger {
	return Ledger{
		SchemaVersion: LedgerSchemaVersion,
		Repository:    "gasserp/probing-data",
		Sources:       []LedgerSource{},
		Periods:       map[string]PeriodLedger{},
	}
}

func TestApplyPayloadCountsHTTPRules(t *testing.T) {
	ledger := emptyLedger()
	payload := rulesPayload(
		httpRecord("2001:db8::1", "/index.php",
			[]protocol.HourlyBucket{{Hour: rulesTestHour, Count: 3}},
			"http/cve-2018-20062-v1"),
		// One record matching two rules counts under each of them.
		httpRecord("2001:db8::2", "/.env",
			[]protocol.HourlyBucket{{Hour: rulesTestHour, Count: 2}, {Hour: "2026-09-10T20:00:00Z", Count: 1}},
			"http/path-traversal-v1", "http/sensitive-file-v1"),
		protocol.BatchRecord{
			Kind:            protocol.ObservationSSHAuthFailure,
			SourceIP:        "2001:db8::3",
			Username:        "root",
			Count:           4,
			FirstObservedAt: rulesTestHour,
			LastObservedAt:  rulesTestHour,
			HourlyBuckets:   []protocol.HourlyBucket{{Hour: rulesTestHour, Count: 4}},
			RuleIDs:         []string{"ssh/all-attempts-v1"},
		},
	)
	if err := applyPayload(&ledger, payload, false); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]map[string]uint64{
		"hourly\x00" + rulesTestHour:     {"http/cve-2018-20062-v1": 3, "http/path-traversal-v1": 2, "http/sensitive-file-v1": 2},
		"hourly\x002026-09-10T20:00:00Z": {"http/path-traversal-v1": 1, "http/sensitive-file-v1": 1},
		"daily\x002026-09-10":            {"http/cve-2018-20062-v1": 3, "http/path-traversal-v1": 3, "http/sensitive-file-v1": 3},
		"yearly\x002026":                 {"http/cve-2018-20062-v1": 3, "http/path-traversal-v1": 3, "http/sensitive-file-v1": 3},
	} {
		period := ledger.Periods[key]
		if len(period.Rules) != len(want) || period.RulesOverflow != 0 {
			t.Errorf("%q rules = %v (overflow %d), want %v", key, period.Rules, period.RulesOverflow, want)
			continue
		}
		for rule, count := range want {
			if period.Rules[rule] != count {
				t.Errorf("%q rule %s = %d, want %d", key, rule, period.Rules[rule], count)
			}
		}
	}
	// Path counts are unchanged by the extra rule.
	if daily := ledger.Periods["daily\x002026-09-10"]; daily.Paths["/.env"] != 3 || daily.Total != 10 {
		t.Errorf("daily paths = %v, total = %d", daily.Paths, daily.Total)
	}
}

func signedHTTPBatch(t *testing.T, privateKey ed25519.PrivateKey, rules ...string) candidate {
	t.Helper()
	payload := rulesPayload(httpRecord("2001:db8::1", "/index.php",
		[]protocol.HourlyBucket{{Hour: rulesTestHour, Count: 2}}, rules...))
	batch, err := protocol.SignBatch(payload, "key-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := publication.ValidateEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	return candidate{relative: envelope.BlobName, data: data, envelope: envelope}
}

func TestRulesOverflowAtCapWithoutQuarantine(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fullRules := make(map[string]uint64, MaxPeriodDimensionValues)
	for i := range MaxPeriodDimensionValues {
		fullRules[fmt.Sprintf("http/rule-%05d-v1", i)] = 1
	}
	key := "hourly\x00" + rulesTestHour
	ledger := emptyLedger()
	ledger.Periods[key] = PeriodLedger{
		Total:     uint64(MaxPeriodDimensionValues),
		Sources:   map[string]uint64{},
		SourceIPs: map[string]uint64{},
		Usernames: map[string]uint64{},
		Paths:     map[string]uint64{},
		Rules:     fullRules,
	}
	original := cloneLedger(ledger)

	// The known rule still counts; the new one rolls into the overflow.
	item := signedHTTPBatch(t, privateKey, "http/new-rule-v1", "http/rule-00000-v1")
	quarantine := Quarantine{SchemaVersion: QuarantineSchemaVersion, Entries: []QuarantineEntry{}}
	result, err := acceptCandidates(context.Background(), &ledger, []candidate{item}, &quarantine)
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted != 1 || len(quarantine.Entries) != 0 {
		t.Fatalf("rule cardinality exhaustion should overflow, not quarantine: result = %#v, quarantine = %#v", result, quarantine)
	}
	period := ledger.Periods[key]
	if len(period.Rules) != MaxPeriodDimensionValues {
		t.Fatalf("rules map should stay capped at %d entries, got %d", MaxPeriodDimensionValues, len(period.Rules))
	}
	if period.RulesOverflow != 2 {
		t.Errorf("RulesOverflow = %d, want 2", period.RulesOverflow)
	}
	if period.Rules["http/rule-00000-v1"] != 3 {
		t.Errorf("existing rule count = %d, want 3", period.Rules["http/rule-00000-v1"])
	}
	if _, found := period.Rules["http/new-rule-v1"]; found {
		t.Error("a rule past the cap was added to the map")
	}
	if period.Total != uint64(MaxPeriodDimensionValues)+2 {
		t.Errorf("period total = %d, want %d", period.Total, uint64(MaxPeriodDimensionValues)+2)
	}
	// Acceptance works on a copy, so the earlier ledger keeps its own map.
	if before := original.Periods[key]; before.Rules["http/rule-00000-v1"] != 1 || before.RulesOverflow != 0 {
		t.Errorf("accepting a batch changed a cloned ledger's rules: %d, overflow %d", before.Rules["http/rule-00000-v1"], before.RulesOverflow)
	}

	root := t.TempDir()
	ledgerPath := filepath.Join(root, "data", "acceptance-ledger.json")
	if err := writeOutputs(root, ledgerPath, ledger, quarantine); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadLedger(ledgerPath, "gasserp/probing-data")
	if err != nil {
		t.Fatalf("written ledger cannot be loaded: %v", err)
	}
	if reloaded := loaded.Periods[key]; len(reloaded.Rules) != MaxPeriodDimensionValues || reloaded.RulesOverflow != 2 {
		t.Errorf("reloaded rules = %d entries, overflow %d", len(reloaded.Rules), reloaded.RulesOverflow)
	}

	tooMany := cloneLedger(loaded)
	period = tooMany.Periods[key]
	period.Rules["http/one-too-many-v1"] = 1
	tooMany.Periods[key] = period
	if err := validateLedger(tooMany, "gasserp/probing-data"); err == nil {
		t.Error("a rules map over the cap passed validation")
	}
}

func TestPrunePeriodsTrimsOldRules(t *testing.T) {
	old := PeriodLedger{
		Total:     105,
		Sources:   map[string]uint64{},
		SourceIPs: map[string]uint64{},
		Usernames: map[string]uint64{},
		Paths:     map[string]uint64{},
		Rules:     map[string]uint64{},
	}
	for i := range 105 {
		old.Rules[fmt.Sprintf("http/rule-%03d-v1", i)] = 1
	}
	old.Rules["http/rule-104-v1"] = 50
	ledger := emptyLedger()
	ledger.Periods["monthly\x002026-01"] = old
	if err := prunePeriods(&ledger, time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	period := ledger.Periods["monthly\x002026-01"]
	if len(period.Rules) != MaxPublicDimensionValues || period.RulesOverflow != 5 {
		t.Fatalf("old rules = %d entries, overflow %d; want %d and 5", len(period.Rules), period.RulesOverflow, MaxPublicDimensionValues)
	}
	if period.Rules["http/rule-104-v1"] != 50 {
		t.Error("trimming dropped the busiest rule")
	}
}

func TestLedgerWithoutRulesStillLoadsAndCounts(t *testing.T) {
	// A ledger written before rules were tracked has no rules fields.
	path := filepath.Join(t.TempDir(), "acceptance-ledger.json")
	data := `{"schema_version":"probing.acceptance-ledger/v1","repository":"gasserp/probing-data","sources":[],` +
		`"periods":{"hourly\u0000` + rulesTestHour + `":{"total":1,"sources":{"sensor-one/epoch":1},"sources_overflow":0,` +
		`"source_ips":{"2001:db8::9":1},"source_ips_overflow":0,"usernames":{},"usernames_overflow":0,` +
		`"paths":{"/":1},"paths_overflow":0}}}` + "\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	ledger, err := loadLedger(path, "gasserp/probing-data")
	if err != nil {
		t.Fatalf("ledger without rules cannot be loaded: %v", err)
	}
	if err := applyPayload(&ledger, rulesPayload(httpRecord("2001:db8::1", "/",
		[]protocol.HourlyBucket{{Hour: rulesTestHour, Count: 1}}, "http/cve-2024-4577-v1")), false); err != nil {
		t.Fatal(err)
	}
	if got := ledger.Periods["hourly\x00"+rulesTestHour].Rules["http/cve-2024-4577-v1"]; got != 1 {
		t.Errorf("rule count on a pre-rules period = %d, want 1", got)
	}
	// SSH-only periods keep omitting the field.
	encoded, err := json.Marshal(PeriodLedger{Total: 1, Sources: map[string]uint64{}, SourceIPs: map[string]uint64{}, Usernames: map[string]uint64{}, Paths: map[string]uint64{}})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if _, found := fields["rules"]; found {
		t.Errorf("empty rules serialized: %s", encoded)
	}
}

func TestBuildInsightsRules(t *testing.T) {
	withRules := func(total uint64, rules map[string]uint64) PeriodLedger {
		p := period(total, map[string]uint64{"11.0.0.1": total}, 0, map[string]uint64{}, map[string]uint64{"/": total})
		p.Rules = rules
		return p
	}
	ledger := Ledger{Periods: map[string]PeriodLedger{
		"hourly\x002026-11-25T10:00:00Z": withRules(3, map[string]uint64{"http/cve-2017-9841-v1": 2, "http/sensitive-file-v1": 1}),
		"hourly\x002026-11-25T11:00:00Z": withRules(4, map[string]uint64{"http/sensitive-file-v1": 4}),
		// A period written before rules were tracked contributes none.
		"hourly\x002026-11-25T12:00:00Z": withRules(1, nil),
		"yearly\x002026":                 withRules(8, map[string]uint64{"http/cve-2017-9841-v1": 2, "http/sensitive-file-v1": 5}),
	}}
	insights, err := BuildInsights(ledger, nil, Geolocation{}, time.Date(2026, 11, 25, 13, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	want := []ValueTotal{{Value: "http/sensitive-file-v1", Count: 5}, {Value: "http/cve-2017-9841-v1", Count: 2}}
	for _, window := range insights.Windows {
		if len(window.Rules) != len(want) || window.Rules[0] != want[0] || window.Rules[1] != want[1] {
			t.Errorf("%s rules = %+v, want %+v", window.ID, window.Rules, want)
		}
	}

	// Rules are ranked and cut like the other value lists.
	many := map[string]uint64{}
	for i := range insightsTopValues + 5 {
		many[fmt.Sprintf("http/rule-%02d-v1", i)] = uint64(i + 1)
	}
	insights, err = BuildInsights(Ledger{Periods: map[string]PeriodLedger{"yearly\x002026": withRules(1, many)}}, nil, Geolocation{}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rules := insights.Windows[0].Rules
	if len(rules) != insightsTopValues || rules[0].Value != fmt.Sprintf("http/rule-%02d-v1", insightsTopValues+4) {
		t.Errorf("top rules = %d entries starting with %+v", len(rules), rules[0])
	}

	// Windows without HTTP rules publish an empty list, not null.
	insights, err = BuildInsights(Ledger{Periods: map[string]PeriodLedger{"yearly\x002026": withRules(1, nil)}}, nil, Geolocation{}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(insights.Windows[0])
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["rules"]) != "[]" {
		t.Errorf("empty rules encode as %s", fields["rules"])
	}
}
