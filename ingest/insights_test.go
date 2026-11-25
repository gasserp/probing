package ingest

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gasserp/probing/geoip"
)

func insightsGeo(t *testing.T) Geolocation {
	t.Helper()
	dir := t.TempDir()
	countryPath := filepath.Join(dir, "country.csv")
	networkPath := filepath.Join(dir, "asn.csv")
	if err := os.WriteFile(countryPath, []byte("11.0.0.0,11.0.0.255,NL\n12.0.0.0,12.0.0.255,BR\n2001:db8::,2001:db8::ffff,DE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(networkPath, []byte("11.0.0.0,11.0.0.255,64500,\"Example NL\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	countries, err := geoip.LoadCountries(countryPath)
	if err != nil {
		t.Fatal(err)
	}
	networks, err := geoip.LoadNetworks(networkPath)
	if err != nil {
		t.Fatal(err)
	}
	return Geolocation{Countries: countries, Networks: networks, Attribution: &GeoAttribution{Provider: "test"}}
}

func period(total uint64, ips map[string]uint64, overflow uint64, usernames, paths map[string]uint64) PeriodLedger {
	return PeriodLedger{
		Total:             total,
		Sources:           map[string]uint64{"sensor/epoch": total},
		SourceIPs:         ips,
		SourceIPsOverflow: overflow,
		Usernames:         usernames,
		Passwords:         map[string]uint64{},
		Paths:             paths,
	}
}

func TestBuildInsights(t *testing.T) {
	ledger := Ledger{
		UpdatedAt: "2026-11-25T14:00:00Z",
		Sources:   []LedgerSource{{SourceID: "sensor", SourceEpoch: "epoch", Kind: SourceKindDecoy}},
		Periods: map[string]PeriodLedger{
			// Outside the 24h window, inside 7d.
			"hourly\x002026-11-20T10:00:00Z": period(5, map[string]uint64{"12.0.0.1": 5}, 0,
				map[string]uint64{"root": 5}, map[string]uint64{}),
			"hourly\x002026-11-25T11:00:00Z": period(10, map[string]uint64{"11.0.0.1": 6, "2001:db8::1": 3, "13.0.0.1": 1}, 0,
				map[string]uint64{"root": 9}, map[string]uint64{"/.env": 1}),
			"hourly\x002026-11-25T13:00:00Z": period(4, map[string]uint64{"11.0.0.2": 2}, 2,
				map[string]uint64{"admin": 4}, map[string]uint64{}),
			"daily\x002026-11-24": period(1, map[string]uint64{"11.0.0.1": 1}, 0, map[string]uint64{"root": 1}, map[string]uint64{}),
			"daily\x002026-11-25": period(14, map[string]uint64{"11.0.0.1": 6}, 8, map[string]uint64{"root": 13}, map[string]uint64{"/.env": 1}),
			// The rollups publish only top values; insights use the full map.
			"yearly\x002026": period(20, map[string]uint64{"11.0.0.1": 7, "11.0.0.2": 2, "12.0.0.1": 5, "2001:db8::1": 3, "13.0.0.1": 1}, 2,
				map[string]uint64{"root": 15, "admin": 4}, map[string]uint64{"/.env": 1}),
		},
	}
	insights, err := BuildInsights(ledger, nil, insightsGeo(t), time.Date(2026, 11, 25, 14, 30, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if insights.SchemaVersion != InsightsSchemaVersion || insights.Label != PublicLabel || insights.Geolocation == nil {
		t.Fatalf("unexpected header: %+v", insights)
	}
	windows := map[string]InsightsWindow{}
	for _, window := range insights.Windows {
		windows[window.ID] = window
	}
	day := windows["24h"]
	if day.Start != "2026-11-24T14:00:00Z" || day.End != "2026-11-25T14:00:00Z" {
		t.Errorf("24h window spans %s to %s", day.Start, day.End)
	}
	if day.Total != 14 || day.SSH != 13 || day.HTTP != 1 {
		t.Errorf("24h totals = %d/%d/%d", day.Total, day.SSH, day.HTTP)
	}
	wantVersions := IPVersionTotals{IPv4: 9, IPv6: 3, Unattributed: 2, IPv4Addresses: 3, IPv6Addresses: 1, AddressesExact: false}
	if day.IPVersions != wantVersions {
		t.Errorf("24h ip versions = %+v, want %+v", day.IPVersions, wantVersions)
	}
	if day.IPVersions.IPv4+day.IPVersions.IPv6+day.IPVersions.Unattributed != day.Total {
		t.Error("address families do not add up to the total")
	}
	if len(day.Countries) != 2 || day.Countries[0] != (CountryTotal{Code: "NL", Count: 8, IPs: 2}) || day.Countries[1] != (CountryTotal{Code: "DE", Count: 3, IPs: 1}) {
		t.Errorf("24h countries = %+v", day.Countries)
	}
	if day.Unlocated != 1 {
		t.Errorf("24h unlocated = %d", day.Unlocated)
	}
	if day.NetworkCount != 1 || len(day.Networks) != 1 || day.Networks[0] != (NetworkTotal{ASN: 64500, Name: "Example NL", Country: "NL", Count: 8, IPs: 2}) {
		t.Errorf("24h networks = %+v", day.Networks)
	}
	if first := day.SourceIPs[0]; first.Value != "11.0.0.1" || first.Country != "NL" || first.ASN != 64500 {
		t.Errorf("24h top ip = %+v", first)
	}
	if len(day.Sources) != 1 || day.Sources[0].Kind != SourceKindDecoy {
		t.Errorf("24h sources = %+v", day.Sources)
	}
	if week := windows["7d"]; week.Total != 19 || week.Countries[0].Code != "NL" || week.Countries[1].Code != "BR" {
		t.Errorf("7d window = %+v", week)
	}
	all := windows["all"]
	if all.Total != 20 || all.IPVersions.IPv4 != 15 || all.IPVersions.IPv6 != 3 || all.IPVersions.Unattributed != 2 {
		t.Errorf("all window = %+v", all.IPVersions)
	}
	if all.Start != "2026-11-24T00:00:00Z" || all.End != "2026-11-25T14:00:00Z" {
		t.Errorf("all window spans %s to %s", all.Start, all.End)
	}

	// Hourly series is continuous from the first hour to the latest one.
	if len(insights.Hourly) != 5*24+4 || insights.Hourly[0].Start != "2026-11-20T10:00:00Z" {
		t.Fatalf("hourly series has %d points from %s", len(insights.Hourly), insights.Hourly[0].Start)
	}
	last := insights.Hourly[len(insights.Hourly)-1]
	if last.Start != "2026-11-25T13:00:00Z" || last.Total != 4 || last.SourceIPs != nil {
		t.Errorf("last hour = %+v", last)
	}
	if gap := insights.Hourly[len(insights.Hourly)-2]; gap.Total != 0 || gap.SourceIPs == nil || *gap.SourceIPs != 0 {
		t.Errorf("quiet hour = %+v", gap)
	}
	if len(insights.Daily) != 2 || insights.Daily[0].SourceIPs == nil || *insights.Daily[0].SourceIPs != 1 || insights.Daily[1].SourceIPs != nil {
		t.Errorf("daily series = %+v", insights.Daily)
	}
}

func TestBuildInsightsWithoutGeolocation(t *testing.T) {
	ledger := Ledger{Periods: map[string]PeriodLedger{
		"yearly\x002026": period(3, map[string]uint64{"11.0.0.1": 3}, 0, map[string]uint64{"root": 3}, map[string]uint64{}),
	}}
	insights, err := BuildInsights(ledger, nil, Geolocation{Attribution: &GeoAttribution{Provider: "test"}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if insights.Geolocation != nil {
		t.Error("attribution published without a database")
	}
	if len(insights.Windows) != 1 {
		t.Fatalf("windows = %+v", insights.Windows)
	}
	all := insights.Windows[0]
	if all.IPVersions.IPv4 != 3 || all.Unlocated != 3 || len(all.Countries) != 0 || len(all.Networks) != 0 {
		t.Errorf("all window = %+v", all)
	}
}
