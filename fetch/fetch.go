// Package fetch pulls signed batches that sources publish to their own public
// GitHub repositories, so ingestion can validate them alongside batches from
// the maintainer's Blob container. It trusts nothing it downloads: every file
// still goes through the full acceptance checks in package ingest. Fetching
// only bounds what a hostile or broken repository can make the run download.
package fetch

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gasserp/probing/ingest"
	"github.com/gasserp/probing/protocol"
)

const (
	DefaultAPIBaseURL = "https://api.github.com"
	DefaultRawBaseURL = "https://raw.githubusercontent.com"

	// MaxPerSource caps one source's share of a run, so a backlog drains over
	// several hourly runs instead of crowding out other sources.
	MaxPerSource = 48
	MaxTreeBytes = 32 << 20
	MaxRuntime   = 10 * time.Minute

	maxCommitBytes = 256
)

var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

type Options struct {
	Targets    []ingest.FetchTarget
	OutputPath string
	// Token authenticates GitHub API calls. Anonymous calls share a limit of
	// 60 per hour per address, which hosted runners exhaust quickly.
	Token      string
	APIBaseURL string
	RawBaseURL string
	Client     *http.Client
}

type Failure struct {
	SourceID   string
	Repository string
	Err        error
}

type Report struct {
	Fetched  int
	Failures []Failure
}

type entry struct {
	path     string
	sha      string
	size     int64
	sequence string
}

// Run downloads, per target, the lowest-sequence batch files at or after the
// target's next sequence into OutputPath under their blob names. A failure
// in one repository is reported and skipped; only local errors abort the run.
// The file budget keeps the combined input within ingest.MaxInputFiles.
func Run(ctx context.Context, options Options) (Report, error) {
	if options.OutputPath == "" {
		return Report{}, errors.New("output path is required")
	}
	if options.APIBaseURL == "" {
		options.APIBaseURL = DefaultAPIBaseURL
	}
	if options.RawBaseURL == "" {
		options.RawBaseURL = DefaultRawBaseURL
	}
	if options.Client == nil {
		options.Client = &http.Client{Timeout: 30 * time.Second}
	}
	runContext, cancel := context.WithTimeout(ctx, MaxRuntime)
	defer cancel()

	if err := os.MkdirAll(options.OutputPath, 0o755); err != nil {
		return Report{}, fmt.Errorf("create output directory: %w", err)
	}
	existing, err := countJSONFiles(options.OutputPath)
	if err != nil {
		return Report{}, err
	}
	remaining := ingest.MaxInputFiles - existing
	report := Report{Failures: []Failure{}}
	if len(options.Targets) == 0 || remaining <= 0 {
		return report, nil
	}
	perSource := min(MaxPerSource, max(1, remaining/len(options.Targets)))
	for _, target := range options.Targets {
		if remaining <= 0 {
			break
		}
		fetched, err := fetchSource(runContext, options, target, min(perSource, remaining))
		report.Fetched += fetched
		remaining -= fetched
		if err != nil {
			if runContext.Err() != nil {
				return report, fmt.Errorf("fetch sources: %w", runContext.Err())
			}
			var local localError
			if errors.As(err, &local) {
				return report, err
			}
			report.Failures = append(report.Failures, Failure{
				SourceID:   target.SourceID,
				Repository: target.Repository,
				Err:        err,
			})
		}
	}
	return report, nil
}

// localError marks failures of this machine, such as a full disk, which must
// stop the run rather than be blamed on a contributor's repository.
type localError struct{ err error }

func (e localError) Error() string { return e.err.Error() }
func (e localError) Unwrap() error { return e.err }

func fetchSource(ctx context.Context, options Options, target ingest.FetchTarget, limit int) (int, error) {
	commit, err := headCommit(ctx, options, target.Repository)
	if err != nil {
		return 0, err
	}
	entries, err := listBatches(ctx, options, target, commit)
	if err != nil {
		return 0, err
	}
	fetched := 0
	for _, item := range entries {
		if fetched >= limit {
			break
		}
		destination := filepath.Join(options.OutputPath, filepath.FromSlash(item.path))
		if _, err := os.Lstat(destination); err == nil {
			// Already downloaded from the Blob container; that copy is the one
			// the workflow may delete after acceptance.
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return fetched, localError{fmt.Errorf("inspect %s: %w", item.path, err)}
		}
		data, err := download(ctx, options, target.Repository, commit, item)
		if err != nil {
			return fetched, err
		}
		if err := writeNew(destination, data); err != nil {
			return fetched, localError{err}
		}
		fetched++
	}
	return fetched, nil
}

func headCommit(ctx context.Context, options Options, repository string) (string, error) {
	request, err := apiRequest(ctx, options, "/repos/"+repository+"/commits/HEAD")
	if err != nil {
		return "", err
	}
	request.Header.Set("Accept", "application/vnd.github.sha")
	data, err := get(options.Client, request, maxCommitBytes)
	if err != nil {
		return "", fmt.Errorf("resolve default branch: %w", err)
	}
	commit := strings.TrimSpace(string(data))
	if !commitPattern.MatchString(commit) {
		return "", errors.New("resolve default branch: response is not a commit SHA")
	}
	return commit, nil
}

func listBatches(ctx context.Context, options Options, target ingest.FetchTarget, commit string) ([]entry, error) {
	request, err := apiRequest(ctx, options, "/repos/"+target.Repository+"/git/trees/"+commit+"?recursive=1")
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	data, err := get(options.Client, request, MaxTreeBytes)
	if err != nil {
		return nil, fmt.Errorf("list tree: %w", err)
	}
	var tree struct {
		Tree []struct {
			Path string `json:"path"`
			Mode string `json:"mode"`
			Type string `json:"type"`
			SHA  string `json:"sha"`
			Size int64  `json:"size"`
		} `json:"tree"`
		Truncated bool `json:"truncated"`
	}
	if err := json.Unmarshal(data, &tree); err != nil {
		return nil, fmt.Errorf("decode tree: %w", err)
	}
	if tree.Truncated {
		return nil, errors.New("repository tree is too large to list")
	}
	pattern := regexp.MustCompile(
		`^` + regexp.QuoteMeta(target.SourceID+"/"+target.SourceEpoch+"/") +
			`([1-9][0-9]{0,1})-(0|[1-9][0-9]*)/[0-9a-f]{64}\.json$`,
	)
	var entries []entry
	for _, item := range tree.Tree {
		if item.Type != "blob" || (item.Mode != "100644" && item.Mode != "100755") {
			continue
		}
		match := pattern.FindStringSubmatch(item.Path)
		if match == nil || !commitPattern.MatchString(item.SHA) {
			continue
		}
		sequence := match[2]
		if strconv.Itoa(len(sequence)) != match[1] || len(sequence) > protocol.MaxSequenceDigits ||
			sequenceLess(sequence, target.NextSequence) {
			continue
		}
		if item.Size < 1 || item.Size > protocol.MaxEncodedEnvelopeBytes {
			continue
		}
		entries = append(entries, entry{path: item.Path, sha: item.SHA, size: item.Size, sequence: sequence})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].sequence != entries[j].sequence {
			return sequenceLess(entries[i].sequence, entries[j].sequence)
		}
		return entries[i].path < entries[j].path
	})
	return entries, nil
}

func download(ctx context.Context, options Options, repository, commit string, item entry) ([]byte, error) {
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		strings.TrimRight(options.RawBaseURL, "/")+"/"+repository+"/"+commit+"/"+item.path,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("create download request: %w", err)
	}
	data, err := get(options.Client, request, protocol.MaxEncodedEnvelopeBytes)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", item.path, err)
	}
	if int64(len(data)) != item.size || gitBlobSHA(data) != item.sha {
		return nil, fmt.Errorf("download %s: content does not match the listed tree", item.path)
	}
	return data, nil
}

func apiRequest(ctx context.Context, options Options, path string) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(options.APIBaseURL, "/")+path, nil)
	if err != nil {
		return nil, fmt.Errorf("create API request: %w", err)
	}
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if options.Token != "" {
		request.Header.Set("Authorization", "Bearer "+options.Token)
	}
	return request, nil
}

// get never includes a response body in its errors: the body is controlled
// by whoever controls the repository.
func get(client *http.Client, request *http.Request, limit int) ([]byte, error) {
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
		return nil, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("response exceeds %d bytes", limit)
	}
	return data, nil
}

func gitBlobSHA(data []byte) string {
	hash := sha1.New()
	fmt.Fprintf(hash, "blob %d\x00", len(data))
	hash.Write(data)
	return hex.EncodeToString(hash.Sum(nil))
}

// sequenceLess compares canonical unsigned decimal strings.
func sequenceLess(left, right string) bool {
	if len(left) != len(right) {
		return len(left) < len(right)
	}
	return left < right
}

func writeNew(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create batch directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("create batch file: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return fmt.Errorf("write batch file: %w", err)
	}
	return file.Close()
}

func countJSONFiles(root string) (int, error) {
	count := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			count++
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("scan output directory: %w", err)
	}
	return count, nil
}
