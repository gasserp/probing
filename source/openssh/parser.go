package openssh

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/gasserp/probing/protocol"
	"github.com/gasserp/probing/source"
)

var failedAuthentication = regexp.MustCompile(
	`^Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(\S+) from (\S+) port [0-9]+`,
)

type journalRecord struct {
	Cursor            string `json:"__CURSOR"`
	RealtimeTimestamp string `json:"__REALTIME_TIMESTAMP"`
	Message           string `json:"MESSAGE"`
}

func Parse(line []byte) (protocol.Observation, bool, error) {
	var record journalRecord
	if err := source.DecodeJSON(line, &record, false); err != nil {
		return protocol.Observation{}, false, err
	}
	matches := failedAuthentication.FindStringSubmatch(record.Message)
	if matches == nil {
		return protocol.Observation{}, false, nil
	}

	microseconds, err := strconv.ParseInt(record.RealtimeTimestamp, 10, 64)
	if err != nil || microseconds < 0 {
		return protocol.Observation{}, false, errors.New("OpenSSH journal timestamp must be non-negative microseconds")
	}
	observedAt := time.Unix(
		microseconds/1_000_000,
		(microseconds%1_000_000)*1_000,
	).UTC().Format(time.RFC3339Nano)
	eventID, err := source.EventID("openssh", record.Cursor)
	if err != nil {
		return protocol.Observation{}, false, err
	}
	address, err := source.CanonicalIP(matches[2])
	if err != nil {
		return protocol.Observation{}, false, err
	}
	observation := protocol.Observation{
		SchemaVersion: protocol.ObservationSchemaVersion,
		EventID:       eventID,
		Cursor:        record.Cursor,
		Kind:          protocol.ObservationSSHAuthFailure,
		ObservedAt:    observedAt,
		SourceIP:      address,
		SSH: &protocol.SSHObservation{
			Username: matches[1],
		},
	}
	if err := protocol.ValidateObservation(observation); err != nil {
		return protocol.Observation{}, false, fmt.Errorf("validate OpenSSH observation: %w", err)
	}
	return observation, true, nil
}
