package ingest

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gasserp/probing/denylist"
	"github.com/gasserp/probing/geoip"
)

const (
	InsightsSchemaVersion = "probing.insights/v1"

	insightsTopValues   = 25
	insightsTopNetworks = 25
	insightsHourlySpan  = 30 * 24
)

// Geolocation holds the optional databases used to place source addresses.
// Either field may be nil; the insights then omit that dimension.
type Geolocation struct {
	Countries *geoip.Countries
	Networks  *geoip.Networks
	// Attribution is published as-is next to the derived values.
	Attribution *GeoAttribution
}

type GeoAttribution struct {
	Provider        string `json:"provider"`
	URL             string `json:"url"`
	License         string `json:"license"`
	CountryDatabase string `json:"country_database,omitempty"`
	NetworkDatabase string `json:"network_database,omitempty"`
}

// InsightsFile is the dashboard's view of the acceptance ledger. Unlike the
// rollups, which publish only the top values of each dimension, it is built
// from the ledger's full per-period counters, so address-family, country, and
// network totals cover every accepted observation the ledger can attribute.
type InsightsFile struct {
	SchemaVersion string           `json:"schema_version"`
	Label         string           `json:"label"`
	UpdatedAt     string           `json:"updated_at,omitempty"`
	GeneratedAt   string           `json:"generated_at"`
	Geolocation   *GeoAttribution  `json:"geolocation"`
	DenyList      DenyListSummary  `json:"deny_list"`
	Windows       []InsightsWindow `json:"windows"`
	Hourly        []SeriesPoint    `json:"hourly"`
	Daily         []SeriesPoint    `json:"daily"`
}

type DenyListSummary struct {
	Recent     int `json:"recent"`
	Persistent int `json:"persistent"`
}

// SeriesPoint is one hour or day. SourceIPs is the number of distinct source
// addresses, or null where the ledger no longer holds the full set.
type SeriesPoint struct {
	Start     string `json:"start"`
	Total     uint64 `json:"total"`
	SSH       uint64 `json:"ssh"`
	HTTP      uint64 `json:"http"`
	SourceIPs *int   `json:"source_ips"`
}

type InsightsWindow struct {
	ID         string          `json:"id"`
	Start      string          `json:"start"`
	End        string          `json:"end"`
	Total      uint64          `json:"total"`
	SSH        uint64          `json:"ssh"`
	HTTP       uint64          `json:"http"`
	Sources    []SourceTotal   `json:"sources"`
	IPVersions IPVersionTotals `json:"ip_versions"`
	// Countries and Unlocated split the attributed observations
	// (IPVersions.IPv4 + IPVersions.IPv6) by the source's country.
	Countries []CountryTotal `json:"countries"`
	Unlocated uint64         `json:"unlocated"`
	// NetworkCount is the number of distinct networks; Networks lists the
	// busiest of them.
	NetworkCount int            `json:"network_count"`
	Networks     []NetworkTotal `json:"networks"`
	SourceIPs    []IPTotal      `json:"source_ips"`
	Usernames    []ValueTotal   `json:"usernames"`
	Passwords    []ValueTotal   `json:"passwords"`
	Paths        []ValueTotal   `json:"paths"`
}

// IPVersionTotals counts observations by address family. Unattributed
// observations came from addresses beyond the ledger's per-period value cap,
// so their address is unknown. Addresses counts distinct sources;
// AddressesExact is false when some were folded into the overflow.
type IPVersionTotals struct {
	IPv4           uint64 `json:"ipv4"`
	IPv6           uint64 `json:"ipv6"`
	Unattributed   uint64 `json:"unattributed"`
	IPv4Addresses  int    `json:"ipv4_addresses"`
	IPv6Addresses  int    `json:"ipv6_addresses"`
	AddressesExact bool   `json:"addresses_exact"`
}

type CountryTotal struct {
	Code  string `json:"code"`
	Count uint64 `json:"count"`
	IPs   int    `json:"ips"`
}

type NetworkTotal struct {
	ASN     uint32 `json:"asn"`
	Name    string `json:"name"`
	Country string `json:"country,omitempty"`
	Count   uint64 `json:"count"`
	IPs     int    `json:"ips"`
}

type IPTotal struct {
	Value   string `json:"value"`
	Count   uint64 `json:"count"`
	Country string `json:"country,omitempty"`
	ASN     uint32 `json:"asn,omitempty"`
	Network string `json:"network,omitempty"`
}

// WriteInsights renders insights.json from the committed acceptance ledger and
// registry/never-block.json of a checked-out data repository.
func WriteInsights(repositoryPath, repositoryIdentity, outputFile string, geo Geolocation, now time.Time) error {
	ledger, err := loadLedger(filepath.Join(repositoryPath, "data", "acceptance-ledger.json"), repositoryIdentity)
	if err != nil {
		return err
	}
	never, err := denylist.LoadNeverBlock(filepath.Join(repositoryPath, "registry", "never-block.json"))
	if err != nil {
		return err
	}
	insights, err := BuildInsights(ledger, never, geo, now)
	if err != nil {
		return err
	}
	data, err := json.Marshal(insights)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outputFile), 0o755); err != nil {
		return fmt.Errorf("create insights directory: %w", err)
	}
	return os.WriteFile(outputFile, append(data, '\n'), 0o644)
}

type ledgerPeriod struct {
	start time.Time
	PeriodLedger
}

func ledgerPeriods(ledger Ledger, granularity string) ([]ledgerPeriod, error) {
	prefix := granularity + "\x00"
	var output []ledgerPeriod
	for key, accumulator := range ledger.Periods {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		start, _, err := periodRange(granularity, strings.TrimPrefix(key, prefix))
		if err != nil {
			return nil, err
		}
		output = append(output, ledgerPeriod{start, accumulator})
	}
	sort.Slice(output, func(i, j int) bool { return output[i].start.Before(output[j].start) })
	return output, nil
}

// BuildInsights derives the dashboard insights from a validated ledger. The
// rolling windows end at the latest accepted hour, not at now, so a stalled
// ingest shows the last data it has rather than an empty dashboard.
func BuildInsights(ledger Ledger, never []netip.Prefix, geo Geolocation, now time.Time) (InsightsFile, error) {
	output := InsightsFile{
		SchemaVersion: InsightsSchemaVersion,
		Label:         PublicLabel,
		UpdatedAt:     ledger.UpdatedAt,
		GeneratedAt:   now.UTC().Format(time.RFC3339),
		Windows:       []InsightsWindow{},
		Hourly:        []SeriesPoint{},
		Daily:         []SeriesPoint{},
	}
	if geo.Countries != nil || geo.Networks != nil {
		output.Geolocation = geo.Attribution
	}
	recent, persistent := denylist.Build(ledger.DenyList, never, now)
	output.DenyList = DenyListSummary{Recent: len(recent), Persistent: len(persistent)}

	kinds := make(map[string]string, len(ledger.Sources))
	for _, source := range ledger.Sources {
		kinds[source.SourceID+"/"+source.SourceEpoch] = source.Kind
	}
	hourly, err := ledgerPeriods(ledger, "hourly")
	if err != nil {
		return InsightsFile{}, err
	}
	daily, err := ledgerPeriods(ledger, "daily")
	if err != nil {
		return InsightsFile{}, err
	}
	yearly, err := ledgerPeriods(ledger, "yearly")
	if err != nil {
		return InsightsFile{}, err
	}
	lookup := newLocator(geo)

	if len(hourly) > 0 {
		anchor := hourly[len(hourly)-1].start.Add(time.Hour)
		for _, window := range []struct {
			id    string
			hours int
		}{{"24h", 24}, {"7d", 7 * 24}, {"30d", 30 * 24}} {
			start := anchor.Add(-time.Duration(window.hours) * time.Hour)
			var selected []PeriodLedger
			for _, period := range hourly {
				if !period.start.Before(start) {
					selected = append(selected, period.PeriodLedger)
				}
			}
			output.Windows = append(output.Windows, buildWindow(window.id, start, anchor, selected, kinds, lookup))
		}
		output.Hourly = series(hourly, anchor.Add(-insightsHourlySpan*time.Hour), anchor, func(t time.Time) time.Time { return t.Add(time.Hour) })
	}
	if len(yearly) > 0 {
		var selected []PeriodLedger
		for _, period := range yearly {
			selected = append(selected, period.PeriodLedger)
		}
		start := yearly[0].start
		if len(daily) > 0 {
			start = daily[0].start
		}
		end := yearly[len(yearly)-1].start.AddDate(1, 0, 0)
		if len(hourly) > 0 {
			end = hourly[len(hourly)-1].start.Add(time.Hour)
		}
		output.Windows = append(output.Windows, buildWindow("all", start, end, selected, kinds, lookup))
	}
	if len(daily) > 0 {
		output.Daily = series(daily, daily[0].start, daily[len(daily)-1].start.AddDate(0, 0, 1), func(t time.Time) time.Time { return t.AddDate(0, 0, 1) })
	}
	return output, nil
}

// series emits one point per step in [from, to), filling quiet periods with
// zeros so the dashboard can plot a continuous axis.
func series(periods []ledgerPeriod, from, to time.Time, next func(time.Time) time.Time) []SeriesPoint {
	byStart := make(map[time.Time]PeriodLedger, len(periods))
	for _, period := range periods {
		byStart[period.start] = period.PeriodLedger
	}
	if len(periods) > 0 && periods[0].start.After(from) {
		from = periods[0].start
	}
	output := []SeriesPoint{}
	for cursor := from; cursor.Before(to); cursor = next(cursor) {
		point := SeriesPoint{Start: cursor.Format(time.RFC3339)}
		if period, ok := byStart[cursor]; ok {
			point.Total = period.Total
			point.SSH = sumCounts(period.Usernames) + period.UsernamesOverflow
			point.HTTP = sumCounts(period.Paths) + period.PathsOverflow
			if period.SourceIPsOverflow == 0 {
				distinct := len(period.SourceIPs)
				point.SourceIPs = &distinct
			}
		} else {
			zero := 0
			point.SourceIPs = &zero
		}
		output = append(output, point)
	}
	return output
}

func sumCounts(values map[string]uint64) uint64 {
	var total uint64
	for _, count := range values {
		total += count
	}
	return total
}

type location struct {
	address netip.Addr
	country string
	network geoip.Network
	located bool
}

type locator struct {
	geo   Geolocation
	cache map[string]location
}

func newLocator(geo Geolocation) *locator {
	return &locator{geo: geo, cache: make(map[string]location)}
}

func (l *locator) locate(value string) (location, bool) {
	if cached, ok := l.cache[value]; ok {
		return cached, cached.address.IsValid()
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		l.cache[value] = location{}
		return location{}, false
	}
	address = address.Unmap().WithZone("")
	result := location{address: address, country: l.geo.Countries.Country(address)}
	result.network, result.located = l.geo.Networks.Network(address)
	l.cache[value] = result
	return result, true
}

func buildWindow(id string, start, end time.Time, periods []PeriodLedger, kinds map[string]string, lookup *locator) InsightsWindow {
	window := InsightsWindow{
		ID:    id,
		Start: start.UTC().Format(time.RFC3339),
		End:   end.UTC().Format(time.RFC3339),
	}
	sources := map[string]uint64{}
	ips := map[string]uint64{}
	usernames := map[string]uint64{}
	passwords := map[string]uint64{}
	paths := map[string]uint64{}
	exact := true
	for _, period := range periods {
		window.Total += period.Total
		window.SSH += sumCounts(period.Usernames) + period.UsernamesOverflow
		window.HTTP += sumCounts(period.Paths) + period.PathsOverflow
		window.IPVersions.Unattributed += period.SourceIPsOverflow
		if period.SourceIPsOverflow > 0 {
			exact = false
		}
		for _, merge := range []struct{ into, from map[string]uint64 }{
			{sources, period.Sources},
			{ips, period.SourceIPs},
			{usernames, period.Usernames},
			{passwords, period.Passwords},
			{paths, period.Paths},
		} {
			for key, count := range merge.from {
				merge.into[key] += count
			}
		}
	}
	window.IPVersions.AddressesExact = exact
	window.Sources = topSources(sources, kinds)
	window.Usernames = limitValues(topValues(usernames), insightsTopValues)
	window.Passwords = limitValues(topValues(passwords), insightsTopValues)
	window.Paths = limitValues(topValues(paths), insightsTopValues)

	countries := map[string]*CountryTotal{}
	networks := map[uint32]*NetworkTotal{}
	networkCountries := map[uint32]map[string]uint64{}
	for value, count := range ips {
		place, ok := lookup.locate(value)
		if !ok {
			window.IPVersions.Unattributed += count
			continue
		}
		if place.address.Is4() {
			window.IPVersions.IPv4 += count
			window.IPVersions.IPv4Addresses++
		} else {
			window.IPVersions.IPv6 += count
			window.IPVersions.IPv6Addresses++
		}
		if place.country == "" {
			window.Unlocated += count
		} else {
			total := countries[place.country]
			if total == nil {
				total = &CountryTotal{Code: place.country}
				countries[place.country] = total
			}
			total.Count += count
			total.IPs++
		}
		if place.located {
			total := networks[place.network.Number]
			if total == nil {
				total = &NetworkTotal{ASN: place.network.Number, Name: place.network.Name}
				networks[place.network.Number] = total
				networkCountries[place.network.Number] = map[string]uint64{}
			}
			total.Count += count
			total.IPs++
			if place.country != "" {
				networkCountries[place.network.Number][place.country] += count
			}
		}
	}
	window.Countries = make([]CountryTotal, 0, len(countries))
	for _, total := range countries {
		window.Countries = append(window.Countries, *total)
	}
	sort.Slice(window.Countries, func(i, j int) bool {
		if window.Countries[i].Count != window.Countries[j].Count {
			return window.Countries[i].Count > window.Countries[j].Count
		}
		return window.Countries[i].Code < window.Countries[j].Code
	})
	window.Networks = make([]NetworkTotal, 0, len(networks))
	for number, total := range networks {
		// A network spanning several countries is shown under the one most
		// of its observations came from.
		if top := topValues(networkCountries[number]); len(top) > 0 {
			total.Country = top[0].Value
		}
		window.Networks = append(window.Networks, *total)
	}
	sort.Slice(window.Networks, func(i, j int) bool {
		if window.Networks[i].Count != window.Networks[j].Count {
			return window.Networks[i].Count > window.Networks[j].Count
		}
		return window.Networks[i].ASN < window.Networks[j].ASN
	})
	window.NetworkCount = len(window.Networks)
	if len(window.Networks) > insightsTopNetworks {
		window.Networks = window.Networks[:insightsTopNetworks]
	}
	window.SourceIPs = []IPTotal{}
	for _, item := range limitValues(topValues(ips), insightsTopValues) {
		entry := IPTotal{Value: item.Value, Count: item.Count}
		if place, ok := lookup.locate(item.Value); ok {
			entry.Country = place.country
			if place.located {
				entry.ASN = place.network.Number
				entry.Network = place.network.Name
			}
		}
		window.SourceIPs = append(window.SourceIPs, entry)
	}
	return window
}

func limitValues(values []ValueTotal, limit int) []ValueTotal {
	if len(values) > limit {
		return values[:limit]
	}
	return values
}
