// Package denylist keeps per-address evidence from accepted observations and
// renders it as firewall-ready deny lists. See docs/deny-list.md.
package denylist

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"
)

const (
	RecentWindow     = 72 * time.Hour
	PersistentWindow = 30 * 24 * time.Hour
	MaxRecords       = 50_000
	MaxDays          = 31
	MaxSources       = 64

	persistentMinSources = 2
	persistentMinDays    = 3
	dayLayout            = "2006-01-02"
)

// Record is the evidence kept for one address (IPv6: one /64).
type Record struct {
	// LastSeen is the end of the latest qualifying UTC hour bucket.
	LastSeen string `json:"last_seen"`
	// Days lists the UTC days with a qualifying event, ascending.
	Days []string `json:"days"`
	// Sources maps each source_id to its latest qualifying UTC day.
	Sources map[string]string `json:"sources"`
}

// Entry is one listed address or /64 and how long it stays listed.
type Entry struct {
	Prefix  netip.Prefix
	Timeout time.Duration
}

// Key normalizes an address to its list key: IPv4 (including IPv4-mapped
// IPv6) as a single address, IPv6 as its /64.
func Key(address netip.Addr) netip.Prefix {
	address = address.Unmap().WithZone("")
	if address.Is4() {
		return netip.PrefixFrom(address, 32)
	}
	return netip.PrefixFrom(address, 64).Masked()
}

// Observe records a qualifying event reported by sourceID in the UTC hour
// starting at hour.
func Observe(state map[string]Record, key netip.Prefix, sourceID string, hour time.Time) {
	hour = hour.UTC().Truncate(time.Hour)
	record := state[key.String()]
	if end := hour.Add(time.Hour).Format(time.RFC3339); end > record.LastSeen {
		record.LastSeen = end
	}
	day := hour.Format(dayLayout)
	index := sort.SearchStrings(record.Days, day)
	if index == len(record.Days) || record.Days[index] != day {
		record.Days = append(record.Days, "")
		copy(record.Days[index+1:], record.Days[index:])
		record.Days[index] = day
	}
	if len(record.Days) > MaxDays {
		record.Days = record.Days[len(record.Days)-MaxDays:]
	}
	if record.Sources == nil {
		record.Sources = make(map[string]string)
	}
	if day > record.Sources[sourceID] {
		record.Sources[sourceID] = day
	}
	state[key.String()] = record
}

// Prune drops days, sources, and whole records that fell out of the
// persistent window.
func Prune(state map[string]Record, now time.Time) {
	cutoff := now.UTC().Add(-PersistentWindow)
	cutoffStamp := cutoff.Format(time.RFC3339)
	cutoffDay := cutoff.Format(dayLayout)
	for key, record := range state {
		if record.LastSeen <= cutoffStamp {
			delete(state, key)
			continue
		}
		first := sort.SearchStrings(record.Days, cutoffDay)
		record.Days = record.Days[first:]
		for source, day := range record.Sources {
			if day < cutoffDay {
				delete(record.Sources, source)
			}
		}
		state[key] = record
	}
}

// Cap evicts the records with the oldest LastSeen until at most limit remain.
func Cap(state map[string]Record, limit int) {
	if len(state) <= limit {
		return
	}
	keys := make([]string, 0, len(state))
	for key := range state {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		left, right := state[keys[i]].LastSeen, state[keys[j]].LastSeen
		if left != right {
			return left < right
		}
		return keys[i] < keys[j]
	})
	for _, key := range keys[:len(keys)-limit] {
		delete(state, key)
	}
}

// Clone deep-copies state.
func Clone(state map[string]Record) map[string]Record {
	if state == nil {
		return nil
	}
	clone := make(map[string]Record, len(state))
	for key, record := range state {
		sources := make(map[string]string, len(record.Sources))
		for source, day := range record.Sources {
			sources[source] = day
		}
		clone[key] = Record{
			LastSeen: record.LastSeen,
			Days:     append([]string(nil), record.Days...),
			Sources:  sources,
		}
	}
	return clone
}

// Validate checks state loaded from the acceptance ledger.
func Validate(state map[string]Record) error {
	if len(state) > MaxRecords {
		return errors.New("deny list state exceeds the record limit")
	}
	for key, record := range state {
		prefix, err := netip.ParsePrefix(key)
		if err != nil || prefix.String() != key || Key(prefix.Addr()) != prefix {
			return fmt.Errorf("deny list key %q is not canonical", key)
		}
		last, err := time.Parse(time.RFC3339, record.LastSeen)
		if err != nil || last.Format(time.RFC3339) != record.LastSeen {
			return fmt.Errorf("deny list record %q has an invalid last_seen", key)
		}
		if len(record.Days) > MaxDays || len(record.Sources) > MaxSources {
			return fmt.Errorf("deny list record %q exceeds its limits", key)
		}
		for i, day := range record.Days {
			if !validDay(day) || (i > 0 && record.Days[i-1] >= day) {
				return fmt.Errorf("deny list record %q has invalid days", key)
			}
		}
		for source, day := range record.Sources {
			if source == "" || !validDay(day) {
				return fmt.Errorf("deny list record %q has invalid sources", key)
			}
		}
	}
	return nil
}

func validDay(day string) bool {
	parsed, err := time.Parse(dayLayout, day)
	return err == nil && parsed.Format(dayLayout) == day
}

// Build returns the recent and persistent lists at now, leaving out
// special-purpose ranges and anything overlapping never. Both are sorted,
// IPv4 first.
func Build(state map[string]Record, never []netip.Prefix, now time.Time) (recent, persistent []Entry) {
	now = now.UTC()
	cutoffDay := now.Add(-PersistentWindow).Format(dayLayout)
	for key, record := range state {
		prefix, err := netip.ParsePrefix(key)
		if err != nil || Excluded(prefix, never) {
			continue
		}
		last, err := time.Parse(time.RFC3339, record.LastSeen)
		if err != nil {
			continue
		}
		if expiry := last.Add(RecentWindow); expiry.After(now) {
			recent = append(recent, Entry{prefix, ceilSecond(expiry.Sub(now))})
		}
		expiry := last.Add(PersistentWindow)
		if !expiry.After(now) {
			continue
		}
		days := len(record.Days) - sort.SearchStrings(record.Days, cutoffDay)
		sources := 0
		for _, day := range record.Sources {
			if day >= cutoffDay {
				sources++
			}
		}
		if sources >= persistentMinSources || days >= persistentMinDays {
			persistent = append(persistent, Entry{prefix, ceilSecond(expiry.Sub(now))})
		}
	}
	sortEntries(recent)
	sortEntries(persistent)
	return recent, persistent
}

func ceilSecond(duration time.Duration) time.Duration {
	return (duration + time.Second - 1).Truncate(time.Second)
}

func sortEntries(entries []Entry) {
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Prefix.Addr().Less(entries[j].Prefix.Addr())
	})
}

// specialPurpose holds the IPv4 ranges from the IANA special-purpose
// registry and the IPv6 ranges inside 2000::/3 that are not global unicast.
// IPv6 outside 2000::/3 is excluded wholesale.
var specialPurpose = mustPrefixes(
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.88.99.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"2001::/23",
	"2001:db8::/32",
	"2002::/16",
	"3fff::/20",
)

var globalUnicast6 = netip.MustParsePrefix("2000::/3")

// Excluded reports whether prefix must never be listed.
func Excluded(prefix netip.Prefix, never []netip.Prefix) bool {
	if prefix.Addr().Is6() && !globalUnicast6.Contains(prefix.Addr()) {
		return true
	}
	for _, reserved := range specialPurpose {
		if reserved.Overlaps(prefix) {
			return true
		}
	}
	for _, blocked := range never {
		if blocked.Overlaps(prefix) {
			return true
		}
	}
	return false
}

func mustPrefixes(values ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, len(values))
	for i, value := range values {
		prefixes[i] = netip.MustParsePrefix(value)
	}
	return prefixes
}
