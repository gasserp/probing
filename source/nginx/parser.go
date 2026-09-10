package nginx

import (
	"fmt"
	"strings"

	"github.com/gasserp/probing/protocol"
	"github.com/gasserp/probing/source"
)

type accessRecord struct {
	Time       string `json:"time"`
	RemoteAddr string `json:"remote_addr"`
	RequestURI string `json:"request_uri"`
	Request    string `json:"request"`
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
	requestTarget := record.RequestURI
	if requestTarget == "" {
		requestTarget, err = requestTargetFromLine(record.Request)
		if err != nil {
			return protocol.Observation{}, err
		}
	}

	observation := protocol.Observation{
		SchemaVersion: protocol.ObservationSchemaVersion,
		EventID:       eventID,
		Cursor:        cursor,
		Kind:          protocol.ObservationHTTPRequest,
		ObservedAt:    observedAt,
		SourceIP:      address,
		HTTP: &protocol.HTTPObservation{
			RequestTarget: requestTarget,
			Status:        record.Status,
		},
	}
	if err := protocol.ValidateObservation(observation); err != nil {
		return protocol.Observation{}, fmt.Errorf("validate Nginx observation: %w", err)
	}
	return observation, nil
}

func requestTargetFromLine(request string) (string, error) {
	parts := strings.Fields(request)
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid Nginx request line")
	}
	return parts[1], nil
}
