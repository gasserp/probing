package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigAndBuildClassifiers(t *testing.T) {
	path := writeConfig(t, `{
		"database_path":"state.db",
		"adapters":[{"id":"nginx","command":"/usr/local/bin/probing-nginx","args":["--file","/var/log/nginx/probing.log"]}],
		"ssh":{
			"window_seconds":900,
			"pair_threshold":6,
			"distinct_username_threshold":6,
			"excluded_usernames":["deploy"],
			"trusted_cidrs":["192.0.2.0/24"]
		},
		"http":{
			"eligible_statuses":[400,403,404],
			"excluded_exact_paths":["/health"],
			"excluded_path_prefixes":["/downloads/"]
		}
	}`)
	configuration, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	ssh, http, window, err := configuration.classifiers()
	if err != nil {
		t.Fatal(err)
	}
	if ssh == nil || http == nil || window.Seconds() != 900 {
		t.Fatal("config did not produce classifiers")
	}
}

func TestLoadConfigRejectsUnknownAndDuplicateAdapters(t *testing.T) {
	unknown := writeConfig(t, `{
		"database_path":"state.db",
		"adapters":[{"id":"one","command":"adapter"}],
		"unexpected":true
	}`)
	if _, err := loadConfig(unknown); err == nil {
		t.Fatal("config accepted an unknown field")
	}

	duplicate := writeConfig(t, `{
		"database_path":"state.db",
		"adapters":[
			{"id":"one","command":"adapter"},
			{"id":"one","command":"adapter"}
		]
	}`)
	if _, err := loadConfig(duplicate); err == nil {
		t.Fatal("config accepted duplicate adapter IDs")
	}

	invalidThreshold := writeConfig(t, `{
		"database_path":"state.db",
		"adapters":[{"id":"one","command":"adapter"}],
		"ssh":{"pair_threshold":-1}
	}`)
	configuration, err := loadConfig(invalidThreshold)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := configuration.classifiers(); err == nil {
		t.Fatal("config accepted a negative SSH threshold")
	}
}

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
