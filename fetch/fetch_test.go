package fetch

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gasserp/probing/ingest"
)

const (
	testEpoch  = "5d6079de-20e0-4d4b-b955-40eac8f14df8"
	testCommit = "0123456789abcdef0123456789abcdef01234567"
)

type fakeFile struct {
	path string
	data []byte
	mode string
	// served replaces data in the raw download, to simulate a tampered or
	// inconsistent response.
	served []byte
}

type fakeGitHub struct {
	t     *testing.T
	repos map[string][]fakeFile
	// rawAuth records whether any raw download carried credentials.
	rawAuth bool
}

func (f *fakeGitHub) server() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		path := request.URL.Path
		switch {
		case strings.HasPrefix(path, "/api/repos/"):
			if request.Header.Get("Authorization") != "Bearer token" {
				f.t.Errorf("API request without token: %s", path)
			}
			rest := strings.TrimPrefix(path, "/api/repos/")
			parts := strings.SplitN(rest, "/", 3)
			files, ok := f.repos[parts[0]+"/"+parts[1]]
			if !ok {
				http.NotFound(writer, request)
				return
			}
			switch parts[2] {
			case "commits/HEAD":
				if request.Header.Get("Accept") != "application/vnd.github.sha" {
					f.t.Errorf("commit request has Accept %q", request.Header.Get("Accept"))
				}
				fmt.Fprint(writer, testCommit)
			case "git/trees/" + testCommit:
				if request.URL.Query().Get("recursive") != "1" {
					f.t.Error("tree request is not recursive")
				}
				type item struct {
					Path string `json:"path"`
					Mode string `json:"mode"`
					Type string `json:"type"`
					SHA  string `json:"sha"`
					Size int64  `json:"size"`
				}
				tree := []item{{Path: "README.md", Mode: "100644", Type: "blob", SHA: gitBlobSHA([]byte("x")), Size: 1}}
				for _, file := range files {
					mode := file.mode
					if mode == "" {
						mode = "100644"
					}
					tree = append(tree, item{
						Path: file.path, Mode: mode, Type: "blob",
						SHA: gitBlobSHA(file.data), Size: int64(len(file.data)),
					})
				}
				json.NewEncoder(writer).Encode(map[string]any{"tree": tree, "truncated": false})
			default:
				http.NotFound(writer, request)
			}
		case strings.HasPrefix(path, "/raw/"):
			if request.Header.Get("Authorization") != "" {
				f.rawAuth = true
			}
			rest := strings.TrimPrefix(path, "/raw/")
			parts := strings.SplitN(rest, "/", 4)
			if len(parts) != 4 || parts[2] != testCommit {
				http.NotFound(writer, request)
				return
			}
			for _, file := range f.repos[parts[0]+"/"+parts[1]] {
				if file.path == parts[3] {
					if file.served != nil {
						writer.Write(file.served)
					} else {
						writer.Write(file.data)
					}
					return
				}
			}
			http.NotFound(writer, request)
		default:
			http.NotFound(writer, request)
		}
	}))
}

func batchPath(sourceID string, sequence uint64, hashDigit string) string {
	value := strconv.FormatUint(sequence, 10)
	return fmt.Sprintf("%s/%s/%d-%s/%s.json", sourceID, testEpoch, len(value), value, strings.Repeat(hashDigit, 64))
}

func options(server *httptest.Server, output string, targets ...ingest.FetchTarget) Options {
	return Options{
		Targets:    targets,
		OutputPath: output,
		Token:      "token",
		APIBaseURL: server.URL + "/api",
		RawBaseURL: server.URL + "/raw",
		Client:     server.Client(),
	}
}

func TestRunFetchesOnlyUnacceptedBatchesInSequenceOrder(t *testing.T) {
	fake := &fakeGitHub{t: t, repos: map[string][]fakeFile{
		"alice/batches": {
			{path: batchPath("alice-pi", 0, "a"), data: []byte(`{"seq":0}`)},
			{path: batchPath("alice-pi", 1, "b"), data: []byte(`{"seq":1}`)},
			{path: batchPath("alice-pi", 10, "c"), data: []byte(`{"seq":10}`)},
			{path: batchPath("alice-pi", 2, "d"), data: []byte(`{"seq":2}`)},
			// Another source's prefix, a symlink, and a non-canonical sequence.
			{path: batchPath("bob-pi", 3, "e"), data: []byte(`{}`)},
			{path: batchPath("alice-pi", 4, "f"), data: []byte(`{}`), mode: "120000"},
			{path: "alice-pi/" + testEpoch + "/2-05/" + strings.Repeat("0", 64) + ".json", data: []byte(`{}`)},
		},
	}}
	server := fake.server()
	defer server.Close()
	output := t.TempDir()
	report, err := Run(context.Background(), options(server, output, ingest.FetchTarget{
		SourceID: "alice-pi", SourceEpoch: testEpoch, Repository: "alice/batches", NextSequence: "1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if report.Fetched != 3 || len(report.Failures) != 0 {
		t.Fatalf("unexpected report: %#v", report)
	}
	for _, expected := range []struct {
		path string
		data string
	}{
		{batchPath("alice-pi", 1, "b"), `{"seq":1}`},
		{batchPath("alice-pi", 2, "d"), `{"seq":2}`},
		{batchPath("alice-pi", 10, "c"), `{"seq":10}`},
	} {
		data, err := os.ReadFile(filepath.Join(output, filepath.FromSlash(expected.path)))
		if err != nil || string(data) != expected.data {
			t.Errorf("%s: got %q, %v", expected.path, data, err)
		}
	}
	if _, err := os.Stat(filepath.Join(output, filepath.FromSlash(batchPath("alice-pi", 0, "a")))); err == nil {
		t.Error("an already accepted batch was fetched")
	}
	if fake.rawAuth {
		t.Error("the API token was sent to the raw content host")
	}
}

func TestRunIsolatesFailingRepositories(t *testing.T) {
	good := batchPath("carol-pi", 0, "a")
	fake := &fakeGitHub{t: t, repos: map[string][]fakeFile{
		"alice/batches": {
			{path: batchPath("alice-pi", 0, "a"), data: []byte(`{"a":1}`), served: []byte(`{"a":2}`)},
		},
		"carol/batches": {{path: good, data: []byte(`{"c":1}`)}},
	}}
	server := fake.server()
	defer server.Close()
	output := t.TempDir()
	report, err := Run(context.Background(), options(server, output,
		ingest.FetchTarget{SourceID: "alice-pi", SourceEpoch: testEpoch, Repository: "alice/batches", NextSequence: "0"},
		ingest.FetchTarget{SourceID: "bob-pi", SourceEpoch: testEpoch, Repository: "bob/missing", NextSequence: "0"},
		ingest.FetchTarget{SourceID: "carol-pi", SourceEpoch: testEpoch, Repository: "carol/batches", NextSequence: "0"},
	))
	if err != nil {
		t.Fatal(err)
	}
	if report.Fetched != 1 || len(report.Failures) != 2 ||
		report.Failures[0].SourceID != "alice-pi" || report.Failures[1].SourceID != "bob-pi" {
		t.Fatalf("unexpected report: %#v", report)
	}
	if _, err := os.Stat(filepath.Join(output, filepath.FromSlash(good))); err != nil {
		t.Fatal("a healthy source was held back by failing ones")
	}
	if _, err := os.Stat(filepath.Join(output, "alice-pi")); err == nil {
		t.Fatal("content that does not match the tree was written")
	}
}

func TestRunKeepsExistingFilesAndRespectsTheInputBudget(t *testing.T) {
	var files []fakeFile
	for sequence := uint64(0); sequence < 5; sequence++ {
		files = append(files, fakeFile{
			path: batchPath("alice-pi", sequence, "a"),
			data: []byte(fmt.Sprintf(`{"seq":%d}`, sequence)),
		})
	}
	fake := &fakeGitHub{t: t, repos: map[string][]fakeFile{"alice/batches": files}}
	server := fake.server()
	defer server.Close()
	output := t.TempDir()

	// Sequence 0 is already there, as if downloaded from the Blob container.
	existing := filepath.Join(output, filepath.FromSlash(files[0].path))
	if err := os.MkdirAll(filepath.Dir(existing), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(existing, []byte("from blob"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Fill the input up to two files short of ingest's limit.
	for i := 1; i < ingest.MaxInputFiles-2; i++ {
		path := filepath.Join(output, "other", fmt.Sprintf("%d.json", i))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	report, err := Run(context.Background(), options(server, output, ingest.FetchTarget{
		SourceID: "alice-pi", SourceEpoch: testEpoch, Repository: "alice/batches", NextSequence: "0",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if report.Fetched != 2 {
		t.Fatalf("fetched %d files with a budget of 2", report.Fetched)
	}
	if data, _ := os.ReadFile(existing); string(data) != "from blob" {
		t.Fatal("an existing input file was overwritten")
	}
	for _, sequence := range []int{1, 2} {
		if _, err := os.Stat(filepath.Join(output, filepath.FromSlash(files[sequence].path))); err != nil {
			t.Errorf("sequence %d was not fetched first", sequence)
		}
	}
}
