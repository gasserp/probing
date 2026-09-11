package uploader

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gasserp/probing/protocol"
	"github.com/gasserp/probing/publication"
)

const (
	metadataEndpoint  = "http://169.254.169.254/metadata/identity/oauth2/token"
	storageAPIVersion = "2023-11-03"
	maxTokenBytes     = 32 << 10
	maxResponseBytes  = 4 << 10
)

var (
	accountPattern   = regexp.MustCompile(`^[a-z0-9]{3,24}$`)
	containerPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])$`)
)

type Config struct {
	Account      string
	Container    string
	OutboxDir    string
	PollInterval time.Duration
}

type Uploader struct {
	config         Config
	metadataClient *http.Client
	storageClient  *http.Client
	metadataURL    string
	storageBaseURL string
	now            func() time.Time

	tokenMu     sync.Mutex
	accessToken string
	tokenExpiry time.Time
}

func New(config Config) (*Uploader, error) {
	if !accountPattern.MatchString(config.Account) {
		return nil, errors.New("storage account name is invalid")
	}
	if !containerPattern.MatchString(config.Container) {
		return nil, errors.New("storage container name is invalid")
	}
	if config.OutboxDir == "" {
		return nil, errors.New("outbox directory is required")
	}
	if config.PollInterval == 0 {
		config.PollInterval = 15 * time.Second
	}
	if config.PollInterval < time.Second || config.PollInterval > time.Hour {
		return nil, errors.New("poll interval must be between one second and one hour")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
	return &Uploader{
		config:         config,
		metadataClient: client,
		storageClient:  client,
		metadataURL:    metadataEndpoint,
		storageBaseURL: "https://" + config.Account + ".blob.core.windows.net",
		now:            time.Now,
	}, nil
}

func (u *Uploader) Run(ctx context.Context) error {
	if err := u.UploadOnce(ctx); err != nil {
		return err
	}
	ticker := time.NewTicker(u.config.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := u.UploadOnce(ctx); err != nil {
				return err
			}
		}
	}
}

func (u *Uploader) UploadOnce(ctx context.Context) error {
	entries, err := os.ReadDir(u.config.OutboxDir)
	if err != nil {
		return fmt.Errorf("read outbox: %w", err)
	}
	if len(entries) > publication.MaxOutboxFiles {
		return fmt.Errorf("outbox contains more than %d files", publication.MaxOutboxFiles)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "batch-") ||
			!strings.HasSuffix(entry.Name(), ".json") ||
			strings.HasSuffix(entry.Name(), ".receipt.json") {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("outbox envelope must not be a symbolic link")
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("inspect outbox envelope: %w", err)
		}
		if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > protocol.MaxEncodedEnvelopeBytes {
			return errors.New("outbox envelope is not a bounded regular file")
		}
		path := filepath.Join(u.config.OutboxDir, entry.Name())
		data, err := readBounded(path, protocol.MaxEncodedEnvelopeBytes)
		if err != nil {
			return err
		}
		envelope, err := publication.ValidateEnvelope(data)
		if err != nil {
			return fmt.Errorf("validate outbox envelope %q: %w", entry.Name(), err)
		}
		if entry.Name() != envelope.FileName {
			return fmt.Errorf("outbox envelope %q does not have its deterministic name", entry.Name())
		}
		receiptPath := filepath.Join(u.config.OutboxDir, publication.ReceiptFileName(entry.Name()))
		if _, err := os.Stat(receiptPath); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect receipt: %w", err)
		}
		etag, err := u.putEnvelope(ctx, envelope.BlobName, data)
		if err != nil {
			return fmt.Errorf("upload %q: %w", entry.Name(), err)
		}
		receipt, err := publication.EncodeReceipt(publication.Receipt{
			SchemaVersion:  publication.ReceiptSchemaVersion,
			SourceID:       envelope.Batch.Payload.SourceID,
			SourceEpoch:    envelope.Batch.Payload.SourceEpoch,
			Sequence:       envelope.Batch.Payload.Sequence,
			PayloadHash:    envelope.PayloadHash,
			EnvelopeSHA256: envelope.EnvelopeSHA256,
			BlobName:       envelope.BlobName,
			ETag:           etag,
		})
		if err != nil {
			return err
		}
		if err := publication.AtomicWrite(receiptPath, receipt, 0o640); err != nil {
			return err
		}
	}
	return nil
}

func (u *Uploader) putEnvelope(ctx context.Context, blobName string, data []byte) (string, error) {
	token, err := u.token(ctx)
	if err != nil {
		return "", err
	}
	blobURL, err := u.blobURL(blobName)
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, blobURL, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("create blob request: %w", err)
	}
	u.authorize(request, token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("If-None-Match", "*")
	request.Header.Set("x-ms-blob-type", "BlockBlob")
	response, err := u.storageClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("create blob: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusCreated {
		io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
		return validatedETag(response.Header.Get("ETag"))
	}
	io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
	if response.StatusCode != http.StatusConflict && response.StatusCode != http.StatusPreconditionFailed {
		return "", fmt.Errorf("create blob returned HTTP %d", response.StatusCode)
	}
	return u.compareExisting(ctx, blobURL, token, data)
}

func (u *Uploader) compareExisting(ctx context.Context, blobURL, token string, expected []byte) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, blobURL, nil)
	if err != nil {
		return "", fmt.Errorf("create existing blob request: %w", err)
	}
	u.authorize(request, token)
	response, err := u.storageClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("read existing blob: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
		return "", fmt.Errorf("read existing blob returned HTTP %d", response.StatusCode)
	}
	existing, err := io.ReadAll(io.LimitReader(response.Body, protocol.MaxEncodedEnvelopeBytes+1))
	if err != nil {
		return "", fmt.Errorf("read existing blob: %w", err)
	}
	if len(existing) > protocol.MaxEncodedEnvelopeBytes {
		return "", errors.New("existing blob exceeds the envelope size limit")
	}
	if !bytes.Equal(existing, expected) {
		return "", errors.New("existing blob conflicts with immutable envelope bytes")
	}
	return validatedETag(response.Header.Get("ETag"))
}

func (u *Uploader) token(ctx context.Context) (string, error) {
	u.tokenMu.Lock()
	defer u.tokenMu.Unlock()
	if u.accessToken != "" && u.now().UTC().Add(5*time.Minute).Before(u.tokenExpiry) {
		return u.accessToken, nil
	}
	endpoint, err := url.Parse(u.metadataURL)
	if err != nil {
		return "", errors.New("metadata endpoint is invalid")
	}
	query := endpoint.Query()
	query.Set("api-version", "2018-02-01")
	query.Set("resource", "https://storage.azure.com/")
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return "", fmt.Errorf("create metadata request: %w", err)
	}
	request.Header.Set("Metadata", "true")
	response, err := u.metadataClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("request managed identity token: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
		return "", fmt.Errorf("managed identity endpoint returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxTokenBytes+1))
	if err != nil {
		return "", fmt.Errorf("read managed identity token: %w", err)
	}
	if len(data) > maxTokenBytes {
		return "", errors.New("managed identity response exceeds the size limit")
	}
	var tokenResponse struct {
		AccessToken string `json:"access_token"`
		ExpiresOn   string `json:"expires_on"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(data, &tokenResponse); err != nil {
		return "", fmt.Errorf("decode managed identity token: %w", err)
	}
	if tokenResponse.AccessToken == "" || len(tokenResponse.AccessToken) > 16<<10 ||
		!strings.EqualFold(tokenResponse.TokenType, "Bearer") {
		return "", errors.New("managed identity token response is invalid")
	}
	expiresUnix, err := parseUnixSeconds(tokenResponse.ExpiresOn)
	if err != nil {
		return "", err
	}
	expiry := time.Unix(expiresUnix, 0).UTC()
	if !expiry.After(u.now().UTC().Add(time.Minute)) {
		return "", errors.New("managed identity token expires too soon")
	}
	u.accessToken = tokenResponse.AccessToken
	u.tokenExpiry = expiry
	return u.accessToken, nil
}

func (u *Uploader) blobURL(blobName string) (string, error) {
	base, err := url.Parse(u.storageBaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return "", errors.New("storage endpoint is invalid")
	}
	base.Path = "/" + u.config.Container + "/" + blobName
	return base.String(), nil
}

func (u *Uploader) authorize(request *http.Request, token string) {
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("x-ms-date", u.now().UTC().Format(http.TimeFormat))
	request.Header.Set("x-ms-version", storageAPIVersion)
}

func validatedETag(value string) (string, error) {
	receipt := publication.Receipt{
		SchemaVersion:  publication.ReceiptSchemaVersion,
		SourceID:       "test-source",
		SourceEpoch:    "00000000-0000-4000-8000-000000000000",
		Sequence:       "0",
		PayloadHash:    strings.Repeat("0", 64),
		EnvelopeSHA256: strings.Repeat("0", 64),
		BlobName:       "test-source/00000000-0000-4000-8000-000000000000/1-0/" + strings.Repeat("0", 64) + ".json",
		ETag:           value,
	}
	if err := publication.ValidateReceipt(receipt); err != nil {
		return "", errors.New("storage response ETag is missing or invalid")
	}
	return value, nil
}

func readBounded(path string, limit int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open outbox envelope: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("read outbox envelope: %w", err)
	}
	if len(data) == 0 || len(data) > limit {
		return nil, errors.New("outbox envelope is empty or oversized")
	}
	return data, nil
}

func parseUnixSeconds(value string) (int64, error) {
	var seconds int64
	if value == "" {
		return 0, errors.New("managed identity expiry is missing")
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, errors.New("managed identity expiry is invalid")
		}
		if seconds > (1<<63-1-int64(r-'0'))/10 {
			return 0, errors.New("managed identity expiry is invalid")
		}
		seconds = seconds*10 + int64(r-'0')
	}
	return seconds, nil
}
