package publication

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gasserp/probing/protocol"
)

const (
	ReceiptSchemaVersion = "probing.outbox-receipt/v1"
	MaxReceiptBytes      = 4_096
	MaxOutboxFiles       = 256
)

var safeETagPattern = regexp.MustCompile(`^"[0-9A-Za-z._:-]{1,128}"$`)

type Envelope struct {
	Batch          protocol.SignedBatch
	PayloadHash    string
	EnvelopeSHA256 string
	FileName       string
	BlobName       string
}

type Receipt struct {
	SchemaVersion  string `json:"schema_version"`
	SourceID       string `json:"source_id"`
	SourceEpoch    string `json:"source_epoch"`
	Sequence       string `json:"sequence"`
	PayloadHash    string `json:"payload_hash"`
	EnvelopeSHA256 string `json:"envelope_sha256"`
	BlobName       string `json:"blob_name"`
	ETag           string `json:"etag"`
}

func ValidateEnvelope(data []byte) (Envelope, error) {
	batch, err := protocol.DecodeSignedBatch(data)
	if err != nil {
		return Envelope{}, err
	}
	canonicalEnvelope, err := json.Marshal(batch)
	if err != nil {
		return Envelope{}, fmt.Errorf("encode signed batch: %w", err)
	}
	if !bytes.Equal(data, canonicalEnvelope) {
		return Envelope{}, errors.New("signed envelope is not in its exact canonical transport encoding")
	}
	payloadHash, err := protocol.PayloadHash(batch.Payload)
	if err != nil {
		return Envelope{}, err
	}
	envelopeHash := sha256.Sum256(data)
	fileName := "batch-" + batch.Payload.Sequence + "-" + payloadHash + ".json"
	blobName := strings.Join([]string{
		batch.Payload.SourceID,
		batch.Payload.SourceEpoch,
		strconv.Itoa(len(batch.Payload.Sequence)) + "-" + batch.Payload.Sequence,
		payloadHash + ".json",
	}, "/")
	return Envelope{
		Batch:          batch,
		PayloadHash:    payloadHash,
		EnvelopeSHA256: hex.EncodeToString(envelopeHash[:]),
		FileName:       fileName,
		BlobName:       blobName,
	}, nil
}

func ReceiptFileName(envelopeFileName string) string {
	return strings.TrimSuffix(envelopeFileName, ".json") + ".receipt.json"
}

func EncodeReceipt(receipt Receipt) ([]byte, error) {
	if err := ValidateReceipt(receipt); err != nil {
		return nil, err
	}
	data, err := json.Marshal(receipt)
	if err != nil {
		return nil, fmt.Errorf("encode receipt: %w", err)
	}
	if len(data) > MaxReceiptBytes {
		return nil, errors.New("encoded receipt exceeds the size limit")
	}
	return data, nil
}

func DecodeReceipt(data []byte) (Receipt, error) {
	if len(data) == 0 || len(data) > MaxReceiptBytes || !utf8.Valid(data) {
		return Receipt{}, errors.New("receipt is empty, oversized, or invalid UTF-8")
	}
	var receipt Receipt
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return Receipt{}, fmt.Errorf("decode receipt: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Receipt{}, errors.New("receipt contains trailing JSON")
	}
	if err := ValidateReceipt(receipt); err != nil {
		return Receipt{}, err
	}
	canonical, err := json.Marshal(receipt)
	if err != nil {
		return Receipt{}, fmt.Errorf("encode receipt: %w", err)
	}
	if !bytes.Equal(data, canonical) {
		return Receipt{}, errors.New("receipt is not in its canonical transport encoding")
	}
	return receipt, nil
}

func ValidateReceipt(receipt Receipt) error {
	if receipt.SchemaVersion != ReceiptSchemaVersion {
		return errors.New("unsupported receipt schema")
	}
	if err := protocol.ValidateSourceIdentity(receipt.SourceID, receipt.SourceEpoch); err != nil {
		return err
	}
	if receipt.Sequence == "" || len(receipt.Sequence) > protocol.MaxSequenceDigits {
		return errors.New("receipt sequence is invalid")
	}
	for i, r := range receipt.Sequence {
		if r < '0' || r > '9' || (i == 0 && len(receipt.Sequence) > 1 && r == '0') {
			return errors.New("receipt sequence is invalid")
		}
	}
	if !isLowerHex(receipt.PayloadHash, 64) || !isLowerHex(receipt.EnvelopeSHA256, 64) {
		return errors.New("receipt hashes are invalid")
	}
	expectedBlob := strings.Join([]string{
		receipt.SourceID,
		receipt.SourceEpoch,
		strconv.Itoa(len(receipt.Sequence)) + "-" + receipt.Sequence,
		receipt.PayloadHash + ".json",
	}, "/")
	if receipt.BlobName != expectedBlob {
		return errors.New("receipt blob name is not deterministic")
	}
	if !safeETagPattern.MatchString(receipt.ETag) {
		return errors.New("receipt ETag is invalid")
	}
	return nil
}

func AtomicWrite(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".probing-tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tempName := file.Name()
	defer os.Remove(tempName)
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return fmt.Errorf("set temporary file mode: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("publish file: %w", err)
	}
	return SyncDirectory(directory)
}

func SyncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}

func isLowerHex(value string, length int) bool {
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
