package ingest

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/gasserp/probing/denylist"
	"github.com/gasserp/probing/protocol"
)

// applyDenyList records the batch's qualifying events. Every decoy
// observation and every HTTP rule match qualifies. SSH failures on a host
// source qualify only when that address tried at least two different
// usernames within one UTC hour of this batch.
func applyDenyList(ledger *Ledger, payload protocol.BatchPayload, kind string) error {
	if ledger.DenyList == nil {
		ledger.DenyList = make(map[string]denylist.Record)
	}
	type addressHour struct {
		key  netip.Prefix
		hour time.Time
	}
	hostUsernames := make(map[addressHour]map[string]struct{})
	for _, record := range payload.Records {
		address, err := netip.ParseAddr(record.SourceIP)
		if err != nil {
			return fmt.Errorf("parse accepted source ip: %w", err)
		}
		key := denylist.Key(address)
		for _, bucket := range record.HourlyBuckets {
			hour, err := time.Parse(time.RFC3339Nano, bucket.Hour)
			if err != nil {
				return err
			}
			hour = hour.UTC().Truncate(time.Hour)
			if kind == SourceKindHost && record.Kind == protocol.ObservationSSHAuthFailure {
				slot := addressHour{key, hour}
				if hostUsernames[slot] == nil {
					hostUsernames[slot] = make(map[string]struct{})
				}
				hostUsernames[slot][record.Username] = struct{}{}
				continue
			}
			denylist.Observe(ledger.DenyList, key, payload.SourceID, hour)
		}
	}
	for slot, usernames := range hostUsernames {
		if len(usernames) >= 2 {
			denylist.Observe(ledger.DenyList, slot.key, payload.SourceID, slot.hour)
		}
	}
	denylist.Cap(ledger.DenyList, denylist.MaxRecords)
	return nil
}

// WriteDenyLists renders the recent and persistent lists at now from the
// committed acceptance ledger and registry/never-block.json of a checked-out
// data repository into outputPath.
func WriteDenyLists(repositoryPath, repositoryIdentity, outputPath string, now time.Time) error {
	ledger, err := loadLedger(filepath.Join(repositoryPath, "data", "acceptance-ledger.json"), repositoryIdentity)
	if err != nil {
		return err
	}
	never, err := denylist.LoadNeverBlock(filepath.Join(repositoryPath, "registry", "never-block.json"))
	if err != nil {
		return err
	}
	recent, persistent := denylist.Build(ledger.DenyList, never, now)
	if err := os.MkdirAll(outputPath, 0o755); err != nil {
		return fmt.Errorf("create deny list directory: %w", err)
	}
	for _, list := range []struct {
		name    string
		window  time.Duration
		entries []denylist.Entry
	}{
		{"recent", denylist.RecentWindow, recent},
		{"persistent", denylist.PersistentWindow, persistent},
	} {
		files := map[string][]byte{
			list.name + ".txt":   denylist.Text(list.name, list.entries, now),
			list.name + ".nft":   denylist.NFT(list.name, list.entries, now),
			list.name + ".ipset": denylist.IPSet(list.name, list.entries, list.window, now),
		}
		for file, content := range files {
			if err := os.WriteFile(filepath.Join(outputPath, file), content, 0o644); err != nil {
				return fmt.Errorf("write %s: %w", file, err)
			}
		}
	}
	return nil
}
