package ingest

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gasserp/probing/protocol"
)

func validateLedger(ledger Ledger, repository string) error {
	if ledger.SchemaVersion != LedgerSchemaVersion || ledger.Repository != repository {
		return errors.New("acceptance ledger schema or repository identity is invalid")
	}
	if len(ledger.Sources) > MaxRegistered || len(ledger.Periods) > 500_000 {
		return errors.New("acceptance ledger exceeds structural limits")
	}
	if ledger.UpdatedAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, ledger.UpdatedAt); err != nil ||
			!strings.HasSuffix(ledger.UpdatedAt, "Z") {
			return errors.New("acceptance ledger updated_at is invalid")
		}
	}
	seenSources := make(map[string]struct{}, len(ledger.Sources))
	for i, source := range ledger.Sources {
		if err := protocol.ValidateSourceIdentity(source.SourceID, source.SourceEpoch); err != nil {
			return fmt.Errorf("ledger source %d: %w", i, err)
		}
		key := source.SourceID + "\x00" + source.SourceEpoch
		if _, duplicate := seenSources[key]; duplicate {
			return errors.New("acceptance ledger contains duplicate source epochs")
		}
		seenSources[key] = struct{}{}
		if len(source.Batches) > MaxAcceptedBatches {
			return errors.New("acceptance ledger source exceeds the batch limit")
		}
		expected := "0"
		previous := ""
		for _, batch := range source.Batches {
			if batch.Sequence != expected || !lowerHex(batch.PayloadHash, 64) {
				return errors.New("acceptance ledger batch chain is invalid")
			}
			prefix := source.SourceID + "/" + source.SourceEpoch + "/" +
				strconv.Itoa(len(batch.Sequence)) + "-" + batch.Sequence + "/"
			if batch.BlobName != prefix+batch.PayloadHash+".json" {
				return errors.New("acceptance ledger blob name is invalid")
			}
			previous = batch.PayloadHash
			var err error
			expected, err = incrementSequence(expected)
			if err != nil {
				return err
			}
		}
		if source.NextSequence != expected || source.PreviousHash != previous {
			return errors.New("acceptance ledger source head is inconsistent")
		}
	}
	for key, period := range ledger.Periods {
		parts := strings.SplitN(key, "\x00", 2)
		if len(parts) != 2 {
			return errors.New("acceptance ledger period key is invalid")
		}
		if _, _, err := periodRange(parts[0], parts[1]); err != nil {
			return err
		}
		if period.Total == 0 || period.Total > protocol.MaxSafeJSONInteger {
			return errors.New("acceptance ledger period total is invalid")
		}
		if period.Sources == nil || period.SourceIPs == nil ||
			period.Usernames == nil || period.Paths == nil {
			return errors.New("acceptance ledger period dimensions are missing")
		}
		for _, values := range []map[string]uint64{
			period.Sources,
			period.SourceIPs,
			period.Usernames,
			period.Paths,
		} {
			for value, count := range values {
				if value == "" || count == 0 || count > protocol.MaxSafeJSONInteger {
					return errors.New("acceptance ledger dimension is invalid")
				}
			}
		}
	}
	return nil
}

func lowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
