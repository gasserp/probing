package classifier

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"
)

const (
	RuleSSHPairThreshold     = "ssh/pair-threshold-v1"
	RuleSSHDistinctUsernames = "ssh/distinct-usernames-v1"
)

type SSHConfig struct {
	Window                    time.Duration
	PairThreshold             int
	DistinctUsernameThreshold int
	MaxSources                int
	MaxEventsPerSource        int
	MaxTotalEvents            int
	ExcludedUsernames         []string
	TrustedNetworks           []netip.Prefix
}

func DefaultSSHConfig() SSHConfig {
	return SSHConfig{
		Window:                    15 * time.Minute,
		PairThreshold:             6,
		DistinctUsernameThreshold: 6,
		MaxSources:                10_000,
		MaxEventsPerSource:        1_000,
		MaxTotalEvents:            100_000,
	}
}

type SSHFailure struct {
	EventID    string
	ObservedAt time.Time
	SourceIP   netip.Addr
	Username   string
}

type Promotion struct {
	Observation SSHFailure
	RuleIDs     []string
	Update      bool
}

type SSHClassifier struct {
	config        SSHConfig
	excludedUsers map[string]struct{}
	sources       map[netip.Addr]*sshSourceState
	totalEvents   int
}

type sshSourceState struct {
	lastSeen       time.Time
	events         []SSHFailure
	activeDistinct bool
	activePairs    map[string]bool
	pairLastSeen   map[string]time.Time
	promotedRules  map[string][]string
}

func NewSSHClassifier(config SSHConfig) (*SSHClassifier, error) {
	if config.Window <= 0 {
		return nil, errors.New("SSH window must be positive")
	}
	if config.PairThreshold < 1 || config.DistinctUsernameThreshold < 1 {
		return nil, errors.New("SSH thresholds must be positive")
	}
	if config.MaxSources < 1 || config.MaxEventsPerSource < 1 || config.MaxTotalEvents < 1 {
		return nil, errors.New("SSH state limits must be positive")
	}
	excluded := make(map[string]struct{}, len(config.ExcludedUsernames))
	for _, username := range config.ExcludedUsernames {
		if username == "" {
			return nil, errors.New("excluded SSH usernames must not be empty")
		}
		excluded[username] = struct{}{}
	}
	for _, prefix := range config.TrustedNetworks {
		if !prefix.IsValid() || prefix != prefix.Masked() ||
			prefix.Addr().Zone() != "" || prefix.Addr() != prefix.Addr().Unmap() {
			return nil, errors.New("trusted SSH network must use canonical unmapped notation without a zone")
		}
	}
	return &SSHClassifier{
		config:        config,
		excludedUsers: excluded,
		sources:       make(map[netip.Addr]*sshSourceState),
	}, nil
}

func (c *SSHClassifier) Process(failure SSHFailure) ([]Promotion, error) {
	ignored, err := c.ShouldIgnore(failure)
	if err != nil {
		return nil, err
	}
	if ignored {
		return nil, nil
	}
	failure.SourceIP = failure.SourceIP.Unmap()

	state := c.sources[failure.SourceIP]
	if state == nil {
		if len(c.sources) >= c.config.MaxSources {
			return nil, errors.New("SSH source state limit exceeded")
		}
		state = &sshSourceState{
			activePairs:   make(map[string]bool),
			pairLastSeen:  make(map[string]time.Time),
			promotedRules: make(map[string][]string),
		}
		c.sources[failure.SourceIP] = state
	}
	if !state.lastSeen.IsZero() && failure.ObservedAt.Before(state.lastSeen) {
		return nil, fmt.Errorf("SSH observations for %s are out of event-time order", failure.SourceIP)
	}
	for _, event := range state.events {
		if event.EventID == failure.EventID {
			return nil, fmt.Errorf("duplicate SSH event ID %q", failure.EventID)
		}
	}

	if !state.lastSeen.IsZero() && failure.ObservedAt.Sub(state.lastSeen) >= c.config.Window {
		c.totalEvents -= len(state.events)
		state.events = nil
		state.activeDistinct = false
		state.activePairs = make(map[string]bool)
		state.pairLastSeen = make(map[string]time.Time)
		state.promotedRules = make(map[string][]string)
	}
	for username, lastPairEvent := range state.pairLastSeen {
		if failure.ObservedAt.Sub(lastPairEvent) >= c.config.Window {
			delete(state.activePairs, username)
			delete(state.pairLastSeen, username)
		}
	}

	cutoff := failure.ObservedAt.Add(-c.config.Window)
	firstRetained := 0
	for firstRetained < len(state.events) && !state.events[firstRetained].ObservedAt.After(cutoff) {
		delete(state.promotedRules, state.events[firstRetained].EventID)
		firstRetained++
	}
	c.totalEvents -= firstRetained
	state.events = state.events[firstRetained:]
	if len(state.events) >= c.config.MaxEventsPerSource {
		return nil, errors.New("SSH per-source event limit exceeded")
	}
	if c.totalEvents >= c.config.MaxTotalEvents {
		return nil, errors.New("SSH total event limit exceeded")
	}
	state.events = append(state.events, failure)
	c.totalEvents++
	state.lastSeen = failure.ObservedAt
	state.pairLastSeen[failure.Username] = failure.ObservedAt

	pairEvents := make([]SSHFailure, 0, c.config.PairThreshold)
	distinctUsers := make(map[string]struct{})
	for _, event := range state.events {
		distinctUsers[event.Username] = struct{}{}
		if event.Username == failure.Username {
			pairEvents = append(pairEvents, event)
		}
	}

	if len(pairEvents) >= c.config.PairThreshold {
		state.activePairs[failure.Username] = true
	}
	if len(distinctUsers) >= c.config.DistinctUsernameThreshold {
		state.activeDistinct = true
	}

	updates := make(map[string]Promotion)
	if state.activePairs[failure.Username] {
		for _, event := range pairEvents {
			c.promote(state, updates, event, RuleSSHPairThreshold)
		}
	}
	if state.activeDistinct {
		for _, event := range state.events {
			c.promote(state, updates, event, RuleSSHDistinctUsernames)
		}
	}

	result := make([]Promotion, 0, len(updates))
	for _, event := range state.events {
		if promotion, ok := updates[event.EventID]; ok {
			result = append(result, promotion)
		}
	}
	return result, nil
}

func (c *SSHClassifier) ShouldIgnore(failure SSHFailure) (bool, error) {
	if failure.EventID == "" {
		return false, errors.New("SSH event ID is required")
	}
	if !failure.SourceIP.IsValid() || failure.SourceIP.IsUnspecified() {
		return false, errors.New("SSH source IP is invalid")
	}
	if failure.SourceIP.Zone() != "" {
		return false, errors.New("SSH source IP must not contain a zone")
	}
	if failure.Username == "" {
		return false, errors.New("SSH username is required")
	}
	if failure.ObservedAt.Location() != time.UTC {
		return false, errors.New("SSH observation time must be UTC")
	}
	if _, excluded := c.excludedUsers[failure.Username]; excluded {
		return true, nil
	}
	address := failure.SourceIP.Unmap()
	for _, prefix := range c.config.TrustedNetworks {
		if prefix.Contains(address) {
			return true, nil
		}
	}
	return false, nil
}

func (c *SSHClassifier) Prune(watermark time.Time) error {
	if watermark.Location() != time.UTC {
		return errors.New("SSH watermark must be UTC")
	}
	for address, state := range c.sources {
		if !state.lastSeen.IsZero() && watermark.Sub(state.lastSeen) >= c.config.Window {
			c.totalEvents -= len(state.events)
			delete(c.sources, address)
		}
	}
	return nil
}

func (c *SSHClassifier) promote(
	state *sshSourceState,
	updates map[string]Promotion,
	event SSHFailure,
	ruleID string,
) {
	previous := state.promotedRules[event.EventID]
	rules := insertSortedUnique(previous, ruleID)
	if slices.Equal(previous, rules) {
		return
	}
	state.promotedRules[event.EventID] = rules
	if update, exists := updates[event.EventID]; exists {
		update.RuleIDs = slices.Clone(rules)
		updates[event.EventID] = update
		return
	}
	updates[event.EventID] = Promotion{
		Observation: event,
		RuleIDs:     slices.Clone(rules),
		Update:      len(previous) > 0,
	}
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
