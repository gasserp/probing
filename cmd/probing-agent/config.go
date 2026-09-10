package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"time"
	"unicode/utf8"

	"github.com/gasserp/probing/classifier"
	"github.com/gasserp/probing/core"
	"github.com/gasserp/probing/source"
)

type config struct {
	DatabasePath string                `json:"database_path"`
	Adapters     []core.AdapterCommand `json:"adapters"`
	SSH          sshConfig             `json:"ssh"`
	HTTP         httpConfig            `json:"http"`
}

type sshConfig struct {
	WindowSeconds             *int     `json:"window_seconds"`
	PairThreshold             *int     `json:"pair_threshold"`
	DistinctUsernameThreshold *int     `json:"distinct_username_threshold"`
	ExcludedUsernames         []string `json:"excluded_usernames"`
	TrustedCIDRs              []string `json:"trusted_cidrs"`
}

type httpConfig struct {
	EligibleStatuses      []int    `json:"eligible_statuses"`
	ExcludedExactPaths    []string `json:"excluded_exact_paths"`
	ExcludedPathPrefixes  []string `json:"excluded_path_prefixes"`
	SensitivePathPatterns []string `json:"sensitive_path_patterns"`
}

func loadConfig(path string) (config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return config{}, fmt.Errorf("read config: %w", err)
	}
	if len(data) == 0 || len(data) > source.MaxLogLineBytes {
		return config{}, errors.New("config file is empty or exceeds 64 KiB")
	}
	if !utf8.Valid(data) {
		return config{}, errors.New("config file is not valid UTF-8")
	}
	var loaded config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&loaded); err != nil {
		return config{}, fmt.Errorf("decode config: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return config{}, errors.New("config contains trailing JSON")
	}
	if loaded.DatabasePath == "" || len(loaded.Adapters) == 0 {
		return config{}, errors.New("database_path and at least one adapter are required")
	}
	seen := make(map[string]struct{}, len(loaded.Adapters))
	for _, adapter := range loaded.Adapters {
		if adapter.ID == "" || adapter.Command == "" {
			return config{}, errors.New("every adapter requires id and command")
		}
		if _, duplicate := seen[adapter.ID]; duplicate {
			return config{}, fmt.Errorf("duplicate adapter ID %q", adapter.ID)
		}
		seen[adapter.ID] = struct{}{}
	}
	return loaded, nil
}

func (c config) classifiers() (*classifier.SSHClassifier, *classifier.HTTPClassifier, time.Duration, error) {
	ssh := classifier.DefaultSSHConfig()
	if c.SSH.WindowSeconds != nil {
		if *c.SSH.WindowSeconds <= 0 || *c.SSH.WindowSeconds > 86_400 {
			return nil, nil, 0, errors.New("ssh.window_seconds must be between 1 and 86400")
		}
		ssh.Window = time.Duration(*c.SSH.WindowSeconds) * time.Second
	}
	if c.SSH.PairThreshold != nil {
		ssh.PairThreshold = *c.SSH.PairThreshold
	}
	if c.SSH.DistinctUsernameThreshold != nil {
		ssh.DistinctUsernameThreshold = *c.SSH.DistinctUsernameThreshold
	}
	ssh.ExcludedUsernames = c.SSH.ExcludedUsernames
	for _, value := range c.SSH.TrustedCIDRs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("parse trusted CIDR %q: %w", value, err)
		}
		ssh.TrustedNetworks = append(ssh.TrustedNetworks, prefix)
	}
	sshClassifier, err := classifier.NewSSHClassifier(ssh)
	if err != nil {
		return nil, nil, 0, err
	}

	http := classifier.DefaultHTTPConfig()
	if len(c.HTTP.EligibleStatuses) > 0 {
		http.EligibleStatuses = c.HTTP.EligibleStatuses
	}
	http.ExcludedExactPaths = c.HTTP.ExcludedExactPaths
	http.ExcludedPathPrefixes = c.HTTP.ExcludedPathPrefixes
	if c.HTTP.SensitivePathPatterns != nil {
		http.SensitivePathPatterns = c.HTTP.SensitivePathPatterns
	}
	httpClassifier, err := classifier.NewHTTPClassifier(http)
	if err != nil {
		return nil, nil, 0, err
	}
	return sshClassifier, httpClassifier, ssh.Window, nil
}
