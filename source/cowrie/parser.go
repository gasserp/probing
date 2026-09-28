package cowrie

import (
	"fmt"
	"unicode/utf8"

	"github.com/gasserp/probing/protocol"
	"github.com/gasserp/probing/source"
)

type eventRecord struct {
	EventID   string `json:"eventid"`
	Timestamp string `json:"timestamp"`
	SourceIP  string `json:"src_ip"`
	Username  string `json:"username"`
	Password  string `json:"password"`
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
			Password: sanitizePassword(record.Password),
		},
	}
	if err := protocol.ValidateObservation(observation); err != nil {
		return protocol.Observation{}, false, fmt.Errorf("validate Cowrie observation: %w", err)
	}
	return observation, true, nil
}

// sanitizePassword keeps the attempted password only when it is a bounded,
// printable UTF-8 string. Anything empty, oversized, or containing control
// characters is dropped so that a malformed secret never rejects the
// otherwise-valid authentication failure it accompanies.
func sanitizePassword(password string) string {
	if password == "" || len(password) > protocol.MaxPasswordBytes || !utf8.ValidString(password) {
		return ""
	}
	for _, r := range password {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return password
}
