package uploader

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
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
	metadataEndpoint   = "http://169.254.169.254/metadata/identity/oauth2/token"
	entraTokenEndpoint = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"
	storageScope       = "https://storage.azure.com/.default"
	storageAPIVersion  = "2023-11-03"
	githubAPIEndpoint  = "https://api.github.com"
	githubAPIVersion   = "2022-11-28"
	maxTokenBytes      = 32 << 10
	maxResponseBytes   = 4 << 10
	maxGitHubResponse  = 64 << 10
	maxCredentialBytes = 1 << 10
)

var (
	accountPattern   = regexp.MustCompile(`^[a-z0-9]{3,24}$`)
	containerPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])$`)
	guidPattern      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	githubRepository = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9]|-[A-Za-z0-9]){0,38}/[A-Za-z0-9._-]{1,100}$`)
)

// Config selects where batches go and with which credential.
//
// With GitHubRepository, each batch is committed under its blob name to that
// public owner/name repository, which the source owns and names in its
// registry entry; CredentialFile holds a token that may write only there.
// This is how contributors publish without any access to the maintainer's
// storage.
//
// Otherwise batches go to the Azure Blob container Account/Container. Without
// ClientID the uploader uses the Azure VM managed identity. With ClientID it
// uses an Entra service principal whose client secret is in CredentialFile.
type Config struct {
	GitHubRepository string
	Account          string
	Container        string
	OutboxDir        string
	PollInterval     time.Duration
	TenantID         string
	ClientID         string
	CredentialFile   string
}

type Uploader struct {
	config         Config
	metadataClient *http.Client
	storageClient  *http.Client
	metadataURL    string
	tokenClient    *http.Client
	tokenURL       string
	clientSecret   string
	storageBaseURL string
	githubToken    string
	githubBaseURL  string
	now            func() time.Time

	tokenMu     sync.Mutex
	accessToken string
	tokenExpiry time.Time
}

func New(config Config) (*Uploader, error) {
	if config.OutboxDir == "" {
		return nil, errors.New("outbox directory is required")
	}
	if config.PollInterval == 0 {
		config.PollInterval = 15 * time.Second
	}
	if config.PollInterval < time.Second || config.PollInterval > time.Hour {
		return nil, errors.New("poll interval must be between one second and one hour")
	}
	var clientSecret, githubToken string
	if config.GitHubRepository != "" {
		if config.Account != "" || config.Container != "" || config.TenantID != "" || config.ClientID != "" {
			return nil, errors.New("a GitHub repository target excludes Azure storage settings")
		}
		if !validGitHubRepository(config.GitHubRepository) {
			return nil, errors.New("GitHub repository must be owner/name")
		}
		token, err := readCredential(config.CredentialFile, "GitHub token")
		if err != nil {
			return nil, err
		}
		githubToken = token
	} else {
		if !accountPattern.MatchString(config.Account) {
			return nil, errors.New("storage account name is invalid")
		}
		if !containerPattern.MatchString(config.Container) {
			return nil, errors.New("storage container name is invalid")
		}
		if config.ClientID != "" || config.TenantID != "" || config.CredentialFile != "" {
			if !guidPattern.MatchString(config.TenantID) || !guidPattern.MatchString(config.ClientID) {
				return nil, errors.New("tenant and client IDs must be lowercase GUIDs")
			}
			secret, err := readCredential(config.CredentialFile, "client secret")
			if err != nil {
				return nil, err
			}
			clientSecret = secret
		}
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
		tokenClient:    client,
		tokenURL:       fmt.Sprintf(entraTokenEndpoint, config.TenantID),
		clientSecret:   clientSecret,
		storageBaseURL: "https://" + config.Account + ".blob.core.windows.net",
		githubToken:    githubToken,
		githubBaseURL:  githubAPIEndpoint,
		now:            time.Now,
	}, nil
}

func validGitHubRepository(value string) bool {
	if !githubRepository.MatchString(value) {
		return false
	}
	name := value[strings.IndexByte(value, '/')+1:]
	return name != "." && name != ".." && !strings.HasSuffix(strings.ToLower(name), ".git")
}

func readCredential(path, name string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("a credential file with the %s is required", name)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open credential file: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxCredentialBytes+1))
	if err != nil {
		return "", fmt.Errorf("read credential file: %w", err)
	}
	secret := strings.TrimRight(string(data), "\r\n")
	if secret == "" || len(data) > maxCredentialBytes || strings.ContainsAny(secret, "\x00\r\n") {
		return "", errors.New("credential file must contain one non-empty line")
	}
	return secret, nil
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
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect outbox envelope: %w", err)
		}
		if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > protocol.MaxEncodedEnvelopeBytes {
			return errors.New("outbox envelope is not a bounded regular file")
		}
		path := filepath.Join(u.config.OutboxDir, entry.Name())
		data, err := readBounded(path, protocol.MaxEncodedEnvelopeBytes)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
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
		put := u.putEnvelope
		if u.config.GitHubRepository != "" {
			put = u.putGitHubEnvelope
		}
		etag, err := put(ctx, envelope.BlobName, data)
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

// putGitHubEnvelope commits the envelope under its blob name through the
// GitHub contents API. Without a "sha" field the API only creates, so like
// Azure's If-None-Match it never replaces an existing file; an existing file
// must hold exactly these bytes. The receipt ETag is the Git blob SHA.
func (u *Uploader) putGitHubEnvelope(ctx context.Context, blobName string, data []byte) (string, error) {
	sha := gitBlobSHA(data)
	body, err := json.Marshal(map[string]string{
		"message": "Add batch " + blobName,
		"content": base64.StdEncoding.EncodeToString(data),
	})
	if err != nil {
		return "", fmt.Errorf("encode GitHub request: %w", err)
	}
	contentsURL := u.githubContentsURL(blobName)
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, contentsURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create GitHub request: %w", err)
	}
	u.authorizeGitHub(request)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Content-Type", "application/json")
	response, err := u.storageClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("create GitHub file: %w", err)
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusCreated:
		var created struct {
			Content struct {
				SHA string `json:"sha"`
			} `json:"content"`
		}
		responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxGitHubResponse+1))
		if err != nil {
			return "", fmt.Errorf("read GitHub response: %w", err)
		}
		if len(responseBody) > maxGitHubResponse || json.Unmarshal(responseBody, &created) != nil ||
			created.Content.SHA != sha {
			return "", errors.New("GitHub did not confirm the envelope's blob SHA")
		}
		return `"` + sha + `"`, nil
	case http.StatusUnprocessableEntity, http.StatusConflict:
		// 422: a file already exists at this path (or the request was
		// rejected); 409: the branch moved. Either way, check what is there.
		io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
		return u.compareExistingGitHub(ctx, contentsURL, data, sha, response.StatusCode)
	default:
		io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
		return "", fmt.Errorf("create GitHub file returned HTTP %d", response.StatusCode)
	}
}

func (u *Uploader) compareExistingGitHub(
	ctx context.Context,
	contentsURL string,
	expected []byte,
	sha string,
	createStatus int,
) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, contentsURL, nil)
	if err != nil {
		return "", fmt.Errorf("create existing GitHub file request: %w", err)
	}
	u.authorizeGitHub(request)
	request.Header.Set("Accept", "application/vnd.github.raw+json")
	response, err := u.storageClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("read existing GitHub file: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
		return "", fmt.Errorf("create GitHub file returned HTTP %d", createStatus)
	}
	if response.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
		return "", fmt.Errorf("read existing GitHub file returned HTTP %d", response.StatusCode)
	}
	existing, err := io.ReadAll(io.LimitReader(response.Body, protocol.MaxEncodedEnvelopeBytes+1))
	if err != nil {
		return "", fmt.Errorf("read existing GitHub file: %w", err)
	}
	if !bytes.Equal(existing, expected) {
		return "", errors.New("existing GitHub file conflicts with immutable envelope bytes")
	}
	return `"` + sha + `"`, nil
}

func (u *Uploader) githubContentsURL(blobName string) string {
	return strings.TrimRight(u.githubBaseURL, "/") + "/repos/" + u.config.GitHubRepository + "/contents/" + blobName
}

func (u *Uploader) authorizeGitHub(request *http.Request) {
	request.Header.Set("Authorization", "Bearer "+u.githubToken)
	request.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
	request.Header.Set("User-Agent", "probing-uploader")
}

func gitBlobSHA(data []byte) string {
	hash := sha1.New()
	fmt.Fprintf(hash, "blob %d\x00", len(data))
	hash.Write(data)
	return hex.EncodeToString(hash.Sum(nil))
}

func (u *Uploader) token(ctx context.Context) (string, error) {
	u.tokenMu.Lock()
	defer u.tokenMu.Unlock()
	if u.accessToken != "" && u.now().UTC().Add(5*time.Minute).Before(u.tokenExpiry) {
		return u.accessToken, nil
	}
	var (
		token  string
		expiry time.Time
		err    error
	)
	if u.config.ClientID != "" {
		token, expiry, err = u.clientCredentialsToken(ctx)
	} else {
		token, expiry, err = u.managedIdentityToken(ctx)
	}
	if err != nil {
		return "", err
	}
	if !expiry.After(u.now().UTC().Add(time.Minute)) {
		return "", errors.New("access token expires too soon")
	}
	u.accessToken = token
	u.tokenExpiry = expiry
	return u.accessToken, nil
}

func (u *Uploader) managedIdentityToken(ctx context.Context) (string, time.Time, error) {
	endpoint, err := url.Parse(u.metadataURL)
	if err != nil {
		return "", time.Time{}, errors.New("metadata endpoint is invalid")
	}
	query := endpoint.Query()
	query.Set("api-version", "2018-02-01")
	query.Set("resource", "https://storage.azure.com/")
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("create metadata request: %w", err)
	}
	request.Header.Set("Metadata", "true")
	data, err := u.tokenResponse(u.metadataClient, request, "managed identity")
	if err != nil {
		return "", time.Time{}, err
	}
	var tokenResponse struct {
		AccessToken string `json:"access_token"`
		ExpiresOn   string `json:"expires_on"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(data, &tokenResponse); err != nil {
		return "", time.Time{}, fmt.Errorf("decode managed identity token: %w", err)
	}
	if !validBearer(tokenResponse.AccessToken, tokenResponse.TokenType) {
		return "", time.Time{}, errors.New("managed identity token response is invalid")
	}
	expiresUnix, err := parseUnixSeconds(tokenResponse.ExpiresOn)
	if err != nil {
		return "", time.Time{}, err
	}
	return tokenResponse.AccessToken, time.Unix(expiresUnix, 0).UTC(), nil
}

func (u *Uploader) clientCredentialsToken(ctx context.Context) (string, time.Time, error) {
	endpoint, err := url.Parse(u.tokenURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" {
		return "", time.Time{}, errors.New("token endpoint is invalid")
	}
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", u.config.ClientID)
	form.Set("client_secret", u.clientSecret)
	form.Set("scope", storageScope)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("create token request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	requested := u.now().UTC()
	data, err := u.tokenResponse(u.tokenClient, request, "Entra token endpoint")
	if err != nil {
		return "", time.Time{}, err
	}
	var tokenResponse struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(data, &tokenResponse); err != nil {
		return "", time.Time{}, fmt.Errorf("decode Entra token: %w", err)
	}
	if !validBearer(tokenResponse.AccessToken, tokenResponse.TokenType) ||
		tokenResponse.ExpiresIn <= 0 || tokenResponse.ExpiresIn > 24*60*60 {
		return "", time.Time{}, errors.New("Entra token response is invalid")
	}
	return tokenResponse.AccessToken, requested.Add(time.Duration(tokenResponse.ExpiresIn) * time.Second), nil
}

// tokenResponse never includes the response body in errors: an Entra error
// body can echo request details, and the metadata body is not needed to
// diagnose a status code.
func (u *Uploader) tokenResponse(client *http.Client, request *http.Request, issuer string) ([]byte, error) {
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("request %s token: %w", issuer, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
		return nil, fmt.Errorf("%s returned HTTP %d", issuer, response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxTokenBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s token: %w", issuer, err)
	}
	if len(data) > maxTokenBytes {
		return nil, fmt.Errorf("%s response exceeds the size limit", issuer)
	}
	return data, nil
}

func validBearer(token, tokenType string) bool {
	return token != "" && len(token) <= 16<<10 && strings.EqualFold(tokenType, "Bearer")
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
