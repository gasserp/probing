package source

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gasserp/probing/protocol"
)

const MaxLogLineBytes = 64 * 1024

func DecodeJSON(line []byte, destination any, rejectUnknown bool) error {
	if len(line) == 0 || len(line) > MaxLogLineBytes {
		return fmt.Errorf("log line must contain between 1 and %d bytes", MaxLogLineBytes)
	}
	if !utf8.Valid(line) {
		return errors.New("log line is not valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	if rejectUnknown {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode log line: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("log line contains trailing JSON")
	}
	return nil
}

func EventID(adapterName, cursor string) (string, error) {
	if adapterName == "" || strings.ContainsAny(adapterName, ":\x00\r\n") {
		return "", errors.New("adapter name is invalid")
	}
	if cursor == "" || len(cursor) > protocol.MaxCursorBytes || strings.ContainsAny(cursor, "\x00\r\n") {
		return "", errors.New("source cursor is invalid")
	}
	sum := sha256.Sum256([]byte(cursor))
	return adapterName + ":" + hex.EncodeToString(sum[:]), nil
}

func CanonicalIP(value string) (string, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || address.IsUnspecified() || address.Zone() != "" {
		return "", errors.New("source address is invalid")
	}
	return address.Unmap().String(), nil
}

func UTCTimestamp(value string) (string, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return "", fmt.Errorf("parse observation timestamp: %w", err)
	}
	return parsed.UTC().Format(time.RFC3339Nano), nil
}
