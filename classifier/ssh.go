package classifier

import (
	"errors"
	"net/netip"
	"time"
)

const RuleSSHAllAttempts = "ssh/all-attempts-v1"

type SSHConfig struct {
	ExcludedUsernames []string
	TrustedNetworks   []netip.Prefix
}

func DefaultSSHConfig() SSHConfig {
	return SSHConfig{}
}

type SSHFailure struct {
	EventID    string
	ObservedAt time.Time
	SourceIP   netip.Addr
	Username   string
}

type SSHDecision struct {
	Eligible bool
	RuleIDs  []string
}

type SSHClassifier struct {
	config        SSHConfig
	excludedUsers map[string]struct{}
}

func NewSSHClassifier(config SSHConfig) (*SSHClassifier, error) {
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
	return &SSHClassifier{config: config, excludedUsers: excluded}, nil
}

func (c *SSHClassifier) Classify(failure SSHFailure) (SSHDecision, error) {
	ignored, err := c.shouldIgnore(failure)
	if err != nil {
		return SSHDecision{}, err
	}
	if ignored {
		return SSHDecision{}, nil
	}
	return SSHDecision{Eligible: true, RuleIDs: []string{RuleSSHAllAttempts}}, nil
}

func (c *SSHClassifier) shouldIgnore(failure SSHFailure) (bool, error) {
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