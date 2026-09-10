package cowrie

import (
	"fmt"

	"github.com/gasserp/probing/protocol"
	"github.com/gasserp/probing/source"
)

type eventRecord struct {
	EventID   string `json:"eventid"`
	Timestamp string `json:"timestamp"`
	SourceIP  string `json:"src_ip"`
	Username  string `json:"username"`
}

func Parse(line []byte, cursor string) (protocol.Observation, bool, error) {
	var record eventRecord
	if err := source.DecodeJSON(line, &record, false); err != nil {
		return protocol.Observation{}, false, err
	}
	if record.EventID != "cowrie.login.failed" {
		return protocol.Observation{}, false, nil
	}
	eventID, err := source.EventID("cowrie", cursor)
	if err != nil {
		return protocol.Observation{}, false, err
	}
	address, err := source.CanonicalIP(record.SourceIP)
	if err != nil {
		return protocol.Observation{}, false, err
	}
	observedAt, err := source.UTCTimestamp(record.Timestamp)
	if err != nil {
		return protocol.Observation{}, false, err
	}
	observation := protocol.Observation{
		SchemaVersion: protocol.ObservationSchemaVersion,
		EventID:       eventID,
		Cursor:        cursor,
		Kind:          protocol.ObservationSSHAuthFailure,
		ObservedAt:    observedAt,
		SourceIP:      address,
		SSH: &protocol.SSHObservation{
			Username: record.Username,
		},
	}
	if err := protocol.ValidateObservation(observation); err != nil {
		return protocol.Observation{}, false, fmt.Errorf("validate Cowrie observation: %w", err)
	}
	return observation, true, nil
}
