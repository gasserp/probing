package uploader

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"sync"
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

// TestUploadOnceSkipsEnvelopeRemovedMidScan reproduces the real mid-scan
// race: UploadOnce lists two envelopes, then while it's still busy
// uploading the first one, a concurrent acknowledge() removes the second
// one's file. By the time the loop reaches the second entry, its file is
// gone. UploadOnce must skip it rather than fail.
func TestUploadOnceSkipsEnvelopeRemovedMidScan(t *testing.T) {
	outbox := t.TempDir()

	firstData := signedEnvelope(t)
	firstEnvelope, err := publication.ValidateEnvelope(firstData)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outbox, firstEnvelope.FileName), firstData, 0o640); err != nil {
		t.Fatal(err)
	}
	secondData := secondSignedEnvelope(t)
	secondEnvelope, err := publication.ValidateEnvelope(secondData)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outbox, secondEnvelope.FileName), secondData, 0o640); err != nil {
		t.Fatal(err)
	}

	// UploadOnce processes entries in ascending name order; work out that
	// order ourselves so we know which envelope's file to remove while the
	// other one is still uploading.
	entries, err := os.ReadDir(outbox)
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	if len(entries) != 2 {
		t.Fatalf("outbox before upload = %d entries, want 2", len(entries))
	}
	dataByName := map[string][]byte{
		firstEnvelope.FileName:  firstData,
		secondEnvelope.FileName: secondData,
	}
	blockedName := entries[0].Name()
	removedName := entries[1].Name()
	removedPath := filepath.Join(outbox, removedName)

	metadata := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Metadata") != "true" {
			t.Error("metadata header missing")
		}
		fmt.Fprintf(writer, `{"access_token":"token","expires_on":"%d","token_type":"Bearer"}`,
			time.Now().Add(time.Hour).Unix())
	}))
	defer metadata.Close()

	started := make(chan struct{})
	proceed := make(chan struct{})
	var once sync.Once
	var uploadCount int
	var uploaded []byte
	storage := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPut ||
			request.Header.Get("If-None-Match") != "*" ||
			request.Header.Get("Authorization") != "Bearer token" {
			t.Errorf("unexpected create request: %s %#v", request.Method, request.Header)
		}
		once.Do(func() {
			close(started)
			<-proceed
		})
		uploadCount++
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

	go func() {
		<-started
		os.Remove(removedPath)
		close(proceed)
	}()

	if err := process.UploadOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	if uploadCount != 1 {
		t.Fatalf("upload count = %d, want 1 (only the surviving envelope)", uploadCount)
	}
	if !bytes.Equal(uploaded, dataByName[blockedName]) {
		t.Fatal("uploader uploaded the wrong envelope")
	}
	if _, err := os.Stat(filepath.Join(outbox, publication.ReceiptFileName(blockedName))); err != nil {
		t.Fatalf("surviving envelope should have a receipt: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outbox, publication.ReceiptFileName(removedName))); !os.IsNotExist(err) {
		t.Fatalf("removed envelope should not have a receipt, stat err = %v", err)
	}
}

func secondSignedEnvelope(t *testing.T) []byte {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := protocol.BatchPayload{
		SchemaVersion:     protocol.BatchSchemaVersion,
		SourceID:          "sensor-one",
		SourceEpoch:       "5d6079de-20e0-4d4b-b955-40eac8f14df8",
		Sequence:          "1",
		PreviousBatchHash: "0000000000000000000000000000000000000000000000000000000000000000",
		CreatedAt:         "2026-09-10T20:00:00Z",
		ObservationWindow: protocol.TimeRange{Start: "2026-09-10T19:00:00Z", End: "2026-09-10T20:00:00Z"},
		ClassifierVersion: "classifier-v1",
		Records: []protocol.BatchRecord{{
			Kind:            protocol.ObservationSSHAuthFailure,
			SourceIP:        "2001:db8::2",
			Username:        "admin",
			Count:           1,
			FirstObservedAt: "2026-09-10T19:02:00Z",
			LastObservedAt:  "2026-09-10T19:02:00Z",
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

func TestUploaderUsesClientCredentialsOutsideAzure(t *testing.T) {
	outbox := t.TempDir()
	data := signedEnvelope(t)
	envelope, err := publication.ValidateEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outbox, envelope.FileName), data, 0o640); err != nil {
		t.Fatal(err)
	}
	secretFile := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secretFile, []byte("s3cr3t~value\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	tokenRequests := 0
	entra := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		tokenRequests++
		if err := request.ParseForm(); err != nil {
			t.Error(err)
		}
		if request.Method != http.MethodPost ||
			request.PostForm.Get("grant_type") != "client_credentials" ||
			request.PostForm.Get("client_id") != "22222222-2222-2222-2222-222222222222" ||
			request.PostForm.Get("client_secret") != "s3cr3t~value" ||
			request.PostForm.Get("scope") != "https://storage.azure.com/.default" {
			t.Errorf("unexpected token request: %s %v", request.Method, request.PostForm)
		}
		fmt.Fprint(writer, `{"token_type":"Bearer","expires_in":3599,"access_token":"sp-token"}`)
	}))
	defer entra.Close()
	storage := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer sp-token" {
			t.Errorf("unexpected authorization %q", request.Header.Get("Authorization"))
		}
		writer.Header().Set("ETag", `"0x8DABC123"`)
		writer.WriteHeader(http.StatusCreated)
	}))
	defer storage.Close()
	process, err := New(Config{
		Account:        "probingtest",
		Container:      "pending-batches",
		OutboxDir:      outbox,
		TenantID:       "11111111-1111-1111-1111-111111111111",
		ClientID:       "22222222-2222-2222-2222-222222222222",
		CredentialFile: secretFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	if process.tokenURL != "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/oauth2/v2.0/token" {
		t.Fatalf("token URL = %q", process.tokenURL)
	}
	process.tokenURL = entra.URL
	process.tokenClient = entra.Client()
	process.metadataURL = "http://127.0.0.1:1/unreachable"
	process.storageBaseURL = storage.URL
	process.storageClient = storage.Client()
	if err := process.UploadOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if tokenRequests != 1 {
		t.Fatalf("token requests = %d, want 1", tokenRequests)
	}
	if _, err := os.Stat(filepath.Join(outbox, publication.ReceiptFileName(envelope.FileName))); err != nil {
		t.Fatalf("receipt missing: %v", err)
	}
}

func TestNewRejectsIncompleteClientCredentials(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secretFile, []byte("value"), 0o400); err != nil {
		t.Fatal(err)
	}
	emptyFile := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(emptyFile, []byte("\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	tenant := "11111111-1111-1111-1111-111111111111"
	client := "22222222-2222-2222-2222-222222222222"
	for name, config := range map[string]Config{
		"missing tenant": {ClientID: client, CredentialFile: secretFile},
		"missing secret": {TenantID: tenant, ClientID: client},
		"empty secret":   {TenantID: tenant, ClientID: client, CredentialFile: emptyFile},
		"uppercase GUID": {TenantID: tenant, ClientID: "22222222-2222-2222-2222-22222222222A", CredentialFile: secretFile},
		"secret only":    {CredentialFile: secretFile},
		"missing client": {TenantID: tenant, CredentialFile: secretFile},
	} {
		t.Run(name, func(t *testing.T) {
			config.Account = "probingtest"
			config.Container = "pending-batches"
			config.OutboxDir = t.TempDir()
			if _, err := New(config); err == nil {
				t.Fatal("New() accepted incomplete client credentials")
			}
		})
	}
}

func githubUploader(t *testing.T, outbox string, server *httptest.Server) *Uploader {
	t.Helper()
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("github_pat_example\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	process, err := New(Config{
		GitHubRepository: "alice/probing-batches",
		OutboxDir:        outbox,
		CredentialFile:   tokenFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	process.githubBaseURL = server.URL
	process.storageClient = server.Client()
	return process
}

func outboxWithEnvelope(t *testing.T) (string, []byte, publication.Envelope) {
	t.Helper()
	outbox := t.TempDir()
	data := signedEnvelope(t)
	envelope, err := publication.ValidateEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outbox, envelope.FileName), data, 0o640); err != nil {
		t.Fatal(err)
	}
	return outbox, data, envelope
}

func TestGitHubUploaderCreatesFileUnderBlobName(t *testing.T) {
	outbox, data, envelope := outboxWithEnvelope(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPut ||
			request.URL.Path != "/repos/alice/probing-batches/contents/"+envelope.BlobName ||
			request.Header.Get("Authorization") != "Bearer github_pat_example" ||
			request.Header.Get("X-GitHub-Api-Version") != "2022-11-28" {
			t.Errorf("unexpected request: %s %s %#v", request.Method, request.URL.Path, request.Header)
		}
		var body map[string]string
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if _, replaces := body["sha"]; replaces {
			t.Error("create request may replace an existing file")
		}
		content, err := base64.StdEncoding.DecodeString(body["content"])
		if err != nil || !bytes.Equal(content, data) {
			t.Error("uploader changed immutable envelope bytes")
		}
		writer.WriteHeader(http.StatusCreated)
		fmt.Fprintf(writer, `{"content":{"sha":%q},"commit":{"sha":"abc"}}`, gitBlobSHA(content))
	}))
	defer server.Close()
	if err := githubUploader(t, outbox, server).UploadOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	receiptData, err := os.ReadFile(filepath.Join(outbox, publication.ReceiptFileName(envelope.FileName)))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := publication.DecodeReceipt(receiptData)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.BlobName != envelope.BlobName || receipt.ETag != `"`+gitBlobSHA(data)+`"` {
		t.Fatalf("unexpected receipt: %#v", receipt)
	}
}

func TestGitHubUploaderAcceptsOnlyIdenticalExistingFile(t *testing.T) {
	for name, existingMatches := range map[string]bool{"identical": true, "conflicting": false} {
		t.Run(name, func(t *testing.T) {
			outbox, data, envelope := outboxWithEnvelope(t)
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				switch request.Method {
				case http.MethodPut:
					writer.WriteHeader(http.StatusUnprocessableEntity)
					fmt.Fprint(writer, `{"message":"Invalid request.\n\n\"sha\" wasn't supplied."}`)
				case http.MethodGet:
					if request.Header.Get("Accept") != "application/vnd.github.raw+json" {
						t.Errorf("existing file read has Accept %q", request.Header.Get("Accept"))
					}
					if existingMatches {
						writer.Write(data)
					} else {
						writer.Write(append([]byte(nil), data[:len(data)-1]...))
					}
				}
			}))
			defer server.Close()
			err := githubUploader(t, outbox, server).UploadOnce(context.Background())
			_, receiptErr := os.Stat(filepath.Join(outbox, publication.ReceiptFileName(envelope.FileName)))
			if existingMatches && (err != nil || receiptErr != nil) {
				t.Fatalf("identical existing file not treated as uploaded: %v, %v", err, receiptErr)
			}
			if !existingMatches && (err == nil || receiptErr == nil) {
				t.Fatal("conflicting existing file was treated as uploaded")
			}
		})
	}
}

func TestNewRejectsInvalidGitHubTarget(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("github_pat_example"), 0o400); err != nil {
		t.Fatal(err)
	}
	for name, config := range map[string]Config{
		"missing token":  {GitHubRepository: "alice/batches"},
		"no owner":       {GitHubRepository: "batches", CredentialFile: tokenFile},
		"path traversal": {GitHubRepository: "alice/..", CredentialFile: tokenFile},
		"extra segment":  {GitHubRepository: "alice/batches/x", CredentialFile: tokenFile},
		"with azure": {
			GitHubRepository: "alice/batches", CredentialFile: tokenFile,
			Account: "probingtest", Container: "pending-batches",
		},
	} {
		t.Run(name, func(t *testing.T) {
			config.OutboxDir = t.TempDir()
			if _, err := New(config); err == nil {
				t.Fatal("New() accepted an invalid GitHub target")
			}
		})
	}
}
