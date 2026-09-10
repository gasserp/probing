package nginx

import (
	"fmt"

	"github.com/gasserp/probing/protocol"
	"github.com/gasserp/probing/source"
)

type accessRecord struct {
	Time       string `json:"time"`
	RemoteAddr string `json:"remote_addr"`
	RequestURI string `json:"request_uri"`
	Status     int    `json:"status"`
}

func Parse(line []byte, cursor string) (protocol.Observation, error) {
	var record accessRecord
	if err := source.DecodeJSON(line, &record, true); err != nil {
		return protocol.Observation{}, err
	}
	eventID, err := source.EventID("nginx", cursor)
	if err != nil {
		return protocol.Observation{}, err
	}
	address, err := source.CanonicalIP(record.RemoteAddr)
	if err != nil {
		return protocol.Observation{}, err
	}
	observedAt, err := source.UTCTimestamp(record.Time)
	if err != nil {
		return protocol.Observation{}, err
	}

	observation := protocol.Observation{
		SchemaVersion: protocol.ObservationSchemaVersion,
		EventID:       eventID,
		Cursor:        cursor,
		Kind:          protocol.ObservationHTTPRequest,
		ObservedAt:    observedAt,
		SourceIP:      address,
		HTTP: &protocol.HTTPObservation{
			RequestTarget: record.RequestURI,
			Status:        record.Status,
		},
	}
	if err := protocol.ValidateObservation(observation); err != nil {
		return protocol.Observation{}, fmt.Errorf("validate Nginx observation: %w", err)
	}
	return observation, nil
}
