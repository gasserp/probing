package uploader

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gasserp/probing/protocol"
	"github.com/gasserp/probing/publication"
)

func TestUploaderCreatesBlobAndDurableReceipt(t *testing.T) {
	outbox := t.TempDir()
	data := signedEnvelope(t)
	envelope, err := publication.ValidateEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outbox, envelope.FileName), data, 0o640); err != nil {
		t.Fatal(err)
	}
	metadata := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Metadata") != "true" {
			t.Error("metadata header missing")
		}
		fmt.Fprintf(writer, `{"access_token":"token","expires_on":"%d","token_type":"Bearer"}`,
			time.Now().Add(time.Hour).Unix())
	}))
	defer metadata.Close()
	var uploaded []byte
	storage := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPut ||
			request.Header.Get("If-None-Match") != "*" ||
			request.Header.Get("Authorization") != "Bearer token" {
			t.Errorf("unexpected create request: %s %#v", request.Method, request.Header)
		}
		uploaded, _ = io.ReadAll(request.Body)
		writer.Header().Set("ETag", `"0x8DABC123"`)
		writer.WriteHeader(http.StatusCreated)
	}))
	defer storage.Close()
	process, err := New(Config{
		Account:   "probingtest",
		Container: "pending-batches",
		OutboxDir: outbox,
	})
	if err != nil {
		t.Fatal(err)
	}
	process.metadataURL = metadata.URL
	process.storageBaseURL = storage.URL
	process.metadataClient = metadata.Client()
	process.storageClient = storage.Client()
	if err := process.UploadOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(uploaded, data) {
		t.Fatal("uploader changed immutable envelope bytes")
	}
	receiptData, err := os.ReadFile(filepath.Join(outbox, publication.ReceiptFileName(envelope.FileName)))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := publication.DecodeReceipt(receiptData)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.BlobName != envelope.BlobName || receipt.EnvelopeSHA256 != envelope.EnvelopeSHA256 {
		t.Fatalf("receipt does not bind the envelope: %#v", receipt)
	}
}

func TestUploaderAcceptsOnlyByteIdenticalExistingBlob(t *testing.T) {
	for _, test := range []struct {
		name     string
		existing func([]byte) []byte
		wantErr  bool
	}{
		{name: "identical", existing: func(data []byte) []byte { return data }},
		{name: "conflict", existing: func([]byte) []byte { return []byte(`{}`) }, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			outbox := t.TempDir()
			data := signedEnvelope(t)
			envelope, _ := publication.ValidateEnvelope(data)
			if err := os.WriteFile(filepath.Join(outbox, envelope.FileName), data, 0o640); err != nil {
				t.Fatal(err)
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				switch request.Method {
				case http.MethodGet:
					writer.Header().Set("ETag", `"0x8DABC123"`)
					writer.Write(test.existing(data))
				case http.MethodPut:
					writer.WriteHeader(http.StatusPreconditionFailed)
				}
			}))
			defer server.Close()
			process, err := New(Config{Account: "probingtest", Container: "pending-batches", OutboxDir: outbox})
			if err != nil {
				t.Fatal(err)
			}
			process.storageBaseURL = server.URL
			process.storageClient = server.Client()
			process.accessToken = "token"
			process.tokenExpiry = time.Now().Add(time.Hour)
			err = process.UploadOnce(context.Background())
			if (err != nil) != test.wantErr {
				t.Fatalf("UploadOnce() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func signedEnvelope(t *testing.T) []byte {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := protocol.BatchPayload{
		SchemaVersion:     protocol.BatchSchemaVersion,
		SourceID:          "sensor-one",
		SourceEpoch:       "5d6079de-20e0-4d4b-b955-40eac8f14df8",
		Sequence:          "0",
		CreatedAt:         "2026-09-10T20:00:00Z",
		ObservationWindow: protocol.TimeRange{Start: "2026-09-10T19:00:00Z", End: "2026-09-10T20:00:00Z"},
		ClassifierVersion: "classifier-v1",
		Records: []protocol.BatchRecord{{
			Kind:            protocol.ObservationSSHAuthFailure,
			SourceIP:        "2001:db8::1",
			Username:        "root",
			Count:           1,
			FirstObservedAt: "2026-09-10T19:01:00Z",
			LastObservedAt:  "2026-09-10T19:01:00Z",
			HourlyBuckets:   []protocol.HourlyBucket{{Hour: "2026-09-10T19:00:00Z", Count: 1}},
			RuleIDs:         []string{"ssh/pair-threshold-v1"},
		}},
	}
	batch, err := protocol.SignBatch(payload, "key-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
