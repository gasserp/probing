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
		return HTTPDecision{}, errors.New("HTTP request target must use origin-form")
	}

	path := stripQueryAndFragment(request.RequestTarget)
	if path == "" || len(path) > c.config.MaxPathBytes || !utf8.ValidString(path) {
		return HTTPDecision{}, errors.New("HTTP path is empty, oversized, or invalid UTF-8")
	}
	for _, r := range path {
		if r < 0x20 || r == 0x7f {
			return HTTPDecision{}, errors.New("HTTP path contains a control character")
		}
	}

	representations := []pathRepresentation{{name: "raw", value: path}}
	current := path
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
		"/.git/config",
		"/proc/self/environ",
	} {
		if strings.Contains(path, candidate) {
			return true
		}
	}
	return false
}
