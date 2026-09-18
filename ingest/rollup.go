package ingest

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gasserp/probing/protocol"
)

const (
	MaxPublicDimensionValues = 100
	MaxPeriodDimensionValues = 10_000
	periodRetention          = 31 * 24 * time.Hour
)

func applyPayload(ledger *Ledger, payload protocol.BatchPayload) error {
	for _, record := range payload.Records {
		for _, bucket := range record.HourlyBuckets {
			hour, err := time.Parse(time.RFC3339Nano, bucket.Hour)
			if err != nil {
				return err
			}
			keys := map[string]string{
				"hourly":  hour.Format(time.RFC3339),
				"daily":   hour.Format("2006-01-02"),
				"monthly": hour.Format("2006-01"),
				"yearly":  hour.Format("2006"),
			}
			for granularity, period := range keys {
				key := granularity + "\x00" + period
				accumulator := ledger.Periods[key]
				if accumulator.Sources == nil {
					accumulator = PeriodLedger{
						Sources:   make(map[string]uint64),
						SourceIPs: make(map[string]uint64),
						Usernames: make(map[string]uint64),
						Paths:     make(map[string]uint64),
					}
				}
				if err := addCount(&accumulator.Total, bucket.Count); err != nil {
					return err
				}
				provenance := payload.SourceID + "/" + payload.SourceEpoch
				if err := addMapCount(accumulator.Sources, &accumulator.SourcesOverflow, provenance, bucket.Count); err != nil {
					return err
				}
				if err := addMapCount(accumulator.SourceIPs, &accumulator.SourceIPsOverflow, record.SourceIP, bucket.Count); err != nil {
					return err
				}
				if record.Kind == protocol.ObservationSSHAuthFailure {
					if err := addMapCount(accumulator.Usernames, &accumulator.UsernamesOverflow, record.Username, bucket.Count); err != nil {
						return err
					}
				} else {
					if err := addMapCount(accumulator.Paths, &accumulator.PathsOverflow, record.Path, bucket.Count); err != nil {
						return err
					}
				}
				ledger.Periods[key] = accumulator
			}
		}
	}
	return nil
}

// prunePeriods bounds ledger growth for periods more than 31 days past their
// end. Hourly periods are dropped outright (daily/monthly/yearly rollups
// already retain that history at coarser grain); other granularities keep
// only their top MaxPublicDimensionValues values per dimension, folding the
// remainder into that dimension's overflow count.
func prunePeriods(ledger *Ledger, now time.Time) error {
	cutoff := now.Add(-periodRetention)
	for key, accumulator := range ledger.Periods {
		granularity, period, found := strings.Cut(key, "\x00")
		if !found {
			continue
		}
		_, end, err := periodRange(granularity, period)
		if err != nil {
			return err
		}
		if !end.Before(cutoff) {
			continue
		}
		if granularity == "hourly" {
			delete(ledger.Periods, key)
			continue
		}
		for _, dimension := range []struct {
			values   map[string]uint64
			overflow *uint64
		}{
			{accumulator.Sources, &accumulator.SourcesOverflow},
			{accumulator.SourceIPs, &accumulator.SourceIPsOverflow},
			{accumulator.Usernames, &accumulator.UsernamesOverflow},
			{accumulator.Paths, &accumulator.PathsOverflow},
		} {
			if err := trimToTop(dimension.values, dimension.overflow, MaxPublicDimensionValues); err != nil {
				return err
			}
		}
		ledger.Periods[key] = accumulator
	}
	return nil
}

// trimToTop keeps the limit highest-count entries of values (ties broken by
// key ascending) and folds the rest into overflow.
func trimToTop(values map[string]uint64, overflow *uint64, limit int) error {
	if len(values) <= limit {
		return nil
	}
	type entry struct {
		key   string
		count uint64
	}
	entries := make([]entry, 0, len(values))
	for key, count := range values {
		entries = append(entries, entry{key, count})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].count != entries[j].count {
			return entries[i].count > entries[j].count
		}
		return entries[i].key < entries[j].key
	})
	for _, dropped := range entries[limit:] {
		if err := addCount(overflow, dropped.count); err != nil {
			return err
		}
		delete(values, dropped.key)
	}
	return nil
}

func buildRollup(ledger Ledger, granularity string) (RollupFile, error) {
	output := RollupFile{
		SchemaVersion: RollupSchemaVersion,
		Label:         PublicLabel,
		Granularity:   granularity,
		UpdatedAt:     ledger.UpdatedAt,
		Periods:       []RollupPeriod{},
	}
	prefix := granularity + "\x00"
	var keys []string
	for key := range ledger.Periods {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, strings.TrimPrefix(key, prefix))
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		start, end, err := periodRange(granularity, key)
		if err != nil {
			return RollupFile{}, err
		}
		accumulator := ledger.Periods[prefix+key]
		output.Periods = append(output.Periods, RollupPeriod{
			Start:     start.Format(time.RFC3339),
			End:       end.Format(time.RFC3339),
			Total:     accumulator.Total,
			Sources:   topSources(accumulator.Sources),
			SourceIPs: topValues(accumulator.SourceIPs),
			Usernames: topValues(accumulator.Usernames),
			Paths:     topValues(accumulator.Paths),
		})
	}
	return output, nil
}

func periodRange(granularity, value string) (time.Time, time.Time, error) {
	var layout string
	var add func(time.Time) time.Time
	switch granularity {
	case "hourly":
		layout = time.RFC3339
		add = func(value time.Time) time.Time { return value.Add(time.Hour) }
	case "daily":
		layout = "2006-01-02"
		add = func(value time.Time) time.Time { return value.AddDate(0, 0, 1) }
	case "monthly":
		layout = "2006-01"
		add = func(value time.Time) time.Time { return value.AddDate(0, 1, 0) }
	case "yearly":
		layout = "2006"
		add = func(value time.Time) time.Time { return value.AddDate(1, 0, 0) }
	default:
		return time.Time{}, time.Time{}, errors.New("unsupported rollup granularity")
	}
	start, err := time.ParseInLocation(layout, value, time.UTC)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("parse %s period %q: %w", granularity, value, err)
	}
	return start, add(start), nil
}

func topValues(values map[string]uint64) []ValueTotal {
	output := make([]ValueTotal, 0, len(values))
	for value, count := range values {
		output = append(output, ValueTotal{Value: value, Count: count})
	}
	sort.Slice(output, func(i, j int) bool {
		if output[i].Count != output[j].Count {
			return output[i].Count > output[j].Count
		}
		return output[i].Value < output[j].Value
	})
	if len(output) > MaxPublicDimensionValues {
		output = output[:MaxPublicDimensionValues]
	}
	return output
}

func topSources(values map[string]uint64) []SourceTotal {
	output := make([]SourceTotal, 0, len(values))
	for value, count := range values {
		parts := strings.SplitN(value, "/", 2)
		if len(parts) != 2 {
			continue
		}
		output = append(output, SourceTotal{
			SourceID:    parts[0],
			SourceEpoch: parts[1],
			Count:       count,
		})
	}
	sort.Slice(output, func(i, j int) bool {
		if output[i].Count != output[j].Count {
			return output[i].Count > output[j].Count
		}
		if output[i].SourceID != output[j].SourceID {
			return output[i].SourceID < output[j].SourceID
		}
		return output[i].SourceEpoch < output[j].SourceEpoch
	})
	return output
}

func addMapCount(values map[string]uint64, overflow *uint64, key string, amount uint64) error {
	current, exists := values[key]
	if !exists && len(values) >= MaxPeriodDimensionValues {
		return addCount(overflow, amount)
	}
	if err := addCount(&current, amount); err != nil {
		return err
	}
	values[key] = current
	return nil
}

func addCount(value *uint64, amount uint64) error {
	if amount > protocol.MaxSafeJSONInteger || *value > protocol.MaxSafeJSONInteger-amount {
		return errors.New("rollup count exceeds the safe JSON integer limit")
	}
	*value += amount
	return nil
}
