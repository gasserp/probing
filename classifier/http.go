package classifier

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	RuleHTTPTraversal     = "http/path-traversal-v1"
	RuleHTTPSensitiveFile = "http/sensitive-file-v1"
)

// cveSignatures match probes for known CVEs. Each pattern is matched against
// the lowercased request target, including the query, in its raw and
// percent-decoded forms. The query is only inspected here; it is never
// published, stored, or hashed. Each pattern names the vulnerable endpoint or
// payload itself, not a product's landing page, so fingerprinting alone does
// not match.
var cveSignatures = []struct {
	ruleID  string
	pattern *regexp.Regexp
}{
	// PHPUnit eval-stdin.php remote code execution.
	{"http/cve-2017-9841-v1", regexp.MustCompile(`/phpunit/.*eval-stdin\.php`)},
	// Dasan GPON router authentication bypass (with CVE-2018-10562).
	{"http/cve-2018-10561-v1", regexp.MustCompile(`/gponform/diag_form`)},
	// FortiOS SSL VPN path traversal.
	{"http/cve-2018-13379-v1", regexp.MustCompile(`/remote/fgt_lang`)},
	// ThinkPHP invokefunction remote code execution (also CVE-2019-9082).
	{"http/cve-2018-20062-v1", regexp.MustCompile(`invokefunction`)},
	// Cisco ASA and FTD web services file read.
	{"http/cve-2020-3452-v1", regexp.MustCompile(`/\+cscot\+/`)},
	// Hikvision web server command injection.
	{"http/cve-2021-36260-v1", regexp.MustCompile(`/sdk/weblanguage`)},
	// FortiOS administrative interface authentication bypass.
	{"http/cve-2022-40684-v1", regexp.MustCompile(`/api/v2/cmdb/system/admin`)},
	// TP-Link Archer AX21 locale command injection.
	{"http/cve-2023-1389-v1", regexp.MustCompile(`/cgi-bin/luci/;stok=/locale`)},
	// TBK DVR command injection.
	{"http/cve-2024-3721-v1", regexp.MustCompile(`/device\.rsp\?.*cmd=___s_o_s_t_r_e_a_max___`)},
	// PHP-CGI argument injection.
	{"http/cve-2024-4577-v1", regexp.MustCompile(`\?.*allow_url_include`)},
	// Vite dev server arbitrary file read.
	{"http/cve-2025-30208-v1", regexp.MustCompile(`/@fs/`)},
	// SAP NetWeaver Visual Composer unauthenticated upload.
	{"http/cve-2025-31324-v1", regexp.MustCompile(`/developmentserver/metadatauploader`)},
}

type HTTPConfig struct {
	EligibleStatuses      []int
	ExcludedExactPaths    []string
	ExcludedPathPrefixes  []string
	SensitivePathPatterns []string
	MaxPathBytes          int
}

func DefaultHTTPConfig() HTTPConfig {
	return HTTPConfig{
		EligibleStatuses: []int{400, 403, 404},
		SensitivePathPatterns: []string{
			`(?i)[a-z0-9._%+-]+(?:@|%40)[a-z0-9.-]+\.[a-z]{2,}`,
			`(?i)(?:token|secret|password|api[_-]?key)[=/:%-][^/]+`,
			`eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}`,
		},
		MaxPathBytes: 2_048,
	}
}

type HTTPRequest struct {
	EventID       string
	RequestTarget string
	Status        int
}

type HTTPDecision struct {
	Eligible              bool
	Path                  string
	MatchedRepresentation string
	RuleIDs               []string
}

type HTTPClassifier struct {
	config            HTTPConfig
	statuses          map[int]struct{}
	sensitivePatterns []*regexp.Regexp
}

func NewHTTPClassifier(config HTTPConfig) (*HTTPClassifier, error) {
	if config.MaxPathBytes <= 0 {
		return nil, errors.New("HTTP max path bytes must be positive")
	}
	if len(config.EligibleStatuses) == 0 {
		return nil, errors.New("HTTP eligible statuses are required")
	}
	for _, exact := range config.ExcludedExactPaths {
		if exact == "" {
			return nil, errors.New("HTTP exact path exclusions must not be empty")
		}
	}
	for _, prefix := range config.ExcludedPathPrefixes {
		if prefix == "" {
			return nil, errors.New("HTTP path-prefix exclusions must not be empty")
		}
	}
	statuses := make(map[int]struct{}, len(config.EligibleStatuses))
	for _, status := range config.EligibleStatuses {
		if status < 100 || status > 599 {
			return nil, fmt.Errorf("invalid HTTP status %d", status)
		}
		statuses[status] = struct{}{}
	}
	patterns := make([]*regexp.Regexp, 0, len(config.SensitivePathPatterns))
	for _, expression := range config.SensitivePathPatterns {
		pattern, err := regexp.Compile(expression)
		if err != nil {
			return nil, fmt.Errorf("compile sensitive path pattern: %w", err)
		}
		patterns = append(patterns, pattern)
	}
	return &HTTPClassifier{config: config, statuses: statuses, sensitivePatterns: patterns}, nil
}

func (c *HTTPClassifier) Classify(request HTTPRequest) (HTTPDecision, error) {
	if request.EventID == "" {
		return HTTPDecision{}, errors.New("HTTP event ID is required")
	}
	if _, eligible := c.statuses[request.Status]; !eligible {
		return HTTPDecision{}, nil
	}
	if !strings.HasPrefix(request.RequestTarget, "/") {
		return HTTPDecision{}, nil
	}

	path := stripQueryAndFragment(request.RequestTarget)
	if path == "" || len(path) > c.config.MaxPathBytes || !utf8.ValidString(path) {
		return HTTPDecision{}, nil
	}
	for _, r := range path {
		if r < 0x20 || r == 0x7f {
			return HTTPDecision{}, nil
		}
	}

	representations := decodedRepresentations(path)

	for _, representation := range representations {
		if c.isExcluded(representation.value) || c.containsSensitiveData(representation.value) {
			return HTTPDecision{}, nil
		}
	}

	var rules []string
	matchedRepresentation := ""
	for _, representation := range representations {
		value := strings.ToLower(strings.ReplaceAll(representation.value, `\`, "/"))
		if strings.Contains(value, "../") {
			rules = insertSortedUnique(rules, RuleHTTPTraversal)
			if matchedRepresentation == "" {
				matchedRepresentation = representation.name
			}
		}
		if containsSensitiveFileProbe(value) {
			rules = insertSortedUnique(rules, RuleHTTPSensitiveFile)
			if matchedRepresentation == "" {
				matchedRepresentation = representation.name
			}
		}
	}
	for _, representation := range decodedRepresentations(stripFragment(request.RequestTarget)) {
		value := strings.ToLower(representation.value)
		for _, signature := range cveSignatures {
			if signature.pattern.MatchString(value) {
				rules = insertSortedUnique(rules, signature.ruleID)
				if matchedRepresentation == "" {
					matchedRepresentation = representation.name
				}
			}
		}
	}
	if len(rules) == 0 {
		return HTTPDecision{}, nil
	}

	return HTTPDecision{
		Eligible:              true,
		Path:                  path,
		MatchedRepresentation: matchedRepresentation,
		RuleIDs:               slices.Clone(rules),
	}, nil
}

type pathRepresentation struct {
	name  string
	value string
}

func decodedRepresentations(value string) []pathRepresentation {
	representations := []pathRepresentation{{name: "raw", value: value}}
	current := value
	for pass := 1; pass <= 2; pass++ {
		decoded, err := url.PathUnescape(current)
		if err != nil || decoded == current {
			break
		}
		name := "decoded_once"
		if pass == 2 {
			name = "decoded_twice"
		}
		representations = append(representations, pathRepresentation{name: name, value: decoded})
		current = decoded
	}
	return representations
}

func stripFragment(requestTarget string) string {
	if index := strings.IndexByte(requestTarget, '#'); index >= 0 {
		return requestTarget[:index]
	}
	return requestTarget
}

func stripQueryAndFragment(requestTarget string) string {
	end := len(requestTarget)
	if index := strings.IndexByte(requestTarget, '?'); index >= 0 && index < end {
		end = index
	}
	if index := strings.IndexByte(requestTarget, '#'); index >= 0 && index < end {
		end = index
	}
	return requestTarget[:end]
}

func (c *HTTPClassifier) isExcluded(path string) bool {
	for _, exact := range c.config.ExcludedExactPaths {
		if path == exact {
			return true
		}
	}
	for _, prefix := range c.config.ExcludedPathPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func (c *HTTPClassifier) containsSensitiveData(path string) bool {
	for _, pattern := range c.sensitivePatterns {
		if pattern.MatchString(path) {
			return true
		}
	}
	return false
}

func containsSensitiveFileProbe(path string) bool {
	for _, candidate := range []string{
		"/etc/passwd",
		"/etc/shadow",
		"/windows/win.ini",
		"/.env",
		"/.git/",
		"/proc/self/environ",
		// Credential and secret stores.
		"/.aws/",
		"/.docker/config.json",
		"/.kube/config",
		"/.git-credentials",
		"/.netrc",
		"/.npmrc",
		"/.pypirc",
		"/.htpasswd",
		"/id_rsa",
		"/credentials.json",
		"/google-credentials.json",
		"/application_default_credentials.json",
		"/service-account.json",
		"/secrets.",
		// Application and deployment configuration that holds secrets.
		"/appsettings.",
		"/local.settings.json",
		"/web.config",
		"/wp-config.php",
		"/settings.py",
		"/database.yml",
		"/application.yml",
		"/application.properties",
		"/docker-compose.",
		"/terraform.tfstate",
		"/.gitlab-ci.yml",
		"/.circleci/config.yml",
		// Database dumps.
		"/backup.sql",
		"/dump.sql",
		"/db.sql",
		"/database.sql",
	} {
		if strings.Contains(path, candidate) {
			return true
		}
	}
	return false
}

func insertSortedUnique(values []string, value string) []string {
	index, found := slices.BinarySearch(values, value)
	if found {
		return values
	}
	result := make([]string, len(values)+1)
	copy(result, values[:index])
	result[index] = value
	copy(result[index+1:], values[index:])
	return result
}
