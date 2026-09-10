package classifier

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"
)

func TestSSHPairPromotesCompleteThresholdWindow(t *testing.T) {
	classifier, err := NewSSHClassifier(DefaultSSHConfig())
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 9, 10, 19, 0, 0, 0, time.UTC)
	address := netip.MustParseAddr("2001:db8::10")

	for i := range 5 {
		promotions, err := classifier.Process(sshFailure(i, start.Add(time.Duration(i)*time.Minute), address, "root"))
		if err != nil {
			t.Fatal(err)
		}
		if len(promotions) != 0 {
			t.Fatalf("attempt %d promoted before threshold", i+1)
		}
	}

	promotions, err := classifier.Process(sshFailure(5, start.Add(5*time.Minute), address, "root"))
	if err != nil {
		t.Fatal(err)
	}
	if len(promotions) != 6 {
		t.Fatalf("sixth attempt produced %d promotions, want 6", len(promotions))
	}
	for _, promotion := range promotions {
		if promotion.Update || !slices.Equal(promotion.RuleIDs, []string{RuleSSHPairThreshold}) {
			t.Fatalf("unexpected promotion: %#v", promotion)
		}
	}

	promotions, err = classifier.Process(sshFailure(6, start.Add(6*time.Minute), address, "root"))
	if err != nil {
		t.Fatal(err)
	}
	if len(promotions) != 1 || promotions[0].Observation.EventID != "event-6" {
		t.Fatalf("active episode did not promote only the new observation: %#v", promotions)
	}

	promotions, err = classifier.Process(sshFailure(7, start.Add(21*time.Minute), address, "root"))
	if err != nil {
		t.Fatal(err)
	}
	if len(promotions) != 0 {
		t.Fatalf("expired episode promoted an observation: %#v", promotions)
	}
}

func TestSSHDistinctUsernamesDoNotDoubleCount(t *testing.T) {
	config := DefaultSSHConfig()
	config.PairThreshold = 2
	config.DistinctUsernameThreshold = 2
	classifier, err := NewSSHClassifier(config)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 9, 10, 19, 0, 0, 0, time.UTC)
	address := netip.MustParseAddr("192.0.2.10")

	if promotions, err := classifier.Process(sshFailure(0, start, address, "alice")); err != nil || len(promotions) != 0 {
		t.Fatalf("first observation = %#v, %v", promotions, err)
	}
	promotions, err := classifier.Process(sshFailure(1, start.Add(time.Minute), address, "bob"))
	if err != nil {
		t.Fatal(err)
	}
	if len(promotions) != 2 {
		t.Fatalf("distinct threshold produced %d promotions, want 2", len(promotions))
	}

	promotions, err = classifier.Process(sshFailure(2, start.Add(2*time.Minute), address, "alice"))
	if err != nil {
		t.Fatal(err)
	}
	if len(promotions) != 2 {
		t.Fatalf("overlapping rules produced %d updates, want 2", len(promotions))
	}
	if !promotions[0].Update {
		t.Fatal("existing observation was not marked as an update")
	}
	if promotions[1].Update {
		t.Fatal("new observation was incorrectly marked as an update")
	}
	wantRules := []string{RuleSSHDistinctUsernames, RuleSSHPairThreshold}
	for _, promotion := range promotions {
		if !slices.Equal(promotion.RuleIDs, wantRules) {
			t.Fatalf("rules = %v, want %v", promotion.RuleIDs, wantRules)
		}
	}
}

func TestSSHExclusionsAndOrdering(t *testing.T) {
	config := DefaultSSHConfig()
	config.ExcludedUsernames = []string{"deploy"}
	config.TrustedNetworks = []netip.Prefix{netip.MustParsePrefix("2001:db8:1::/48")}
	classifier, err := NewSSHClassifier(config)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 10, 19, 0, 0, 0, time.UTC)

	if promotions, err := classifier.Process(sshFailure(0, now, netip.MustParseAddr("192.0.2.1"), "deploy")); err != nil || len(promotions) != 0 {
		t.Fatalf("excluded username = %#v, %v", promotions, err)
	}
	if promotions, err := classifier.Process(sshFailure(1, now, netip.MustParseAddr("2001:db8:1::1"), "root")); err != nil || len(promotions) != 0 {
		t.Fatalf("trusted network = %#v, %v", promotions, err)
	}

	address := netip.MustParseAddr("192.0.2.2")
	if _, err := classifier.Process(sshFailure(2, now, address, "root")); err != nil {
		t.Fatal(err)
	}
	if _, err := classifier.Process(sshFailure(3, now.Add(-time.Second), address, "root")); err == nil {
		t.Fatal("out-of-order observation was accepted")
	}
}

func TestSSHNormalizesMappedAddressBeforeTrustedNetworkCheck(t *testing.T) {
	config := DefaultSSHConfig()
	config.TrustedNetworks = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	classifier, err := NewSSHClassifier(config)
	if err != nil {
		t.Fatal(err)
	}
	failure := sshFailure(
		0,
		time.Date(2026, 9, 10, 19, 0, 0, 0, time.UTC),
		netip.MustParseAddr("::ffff:192.0.2.10"),
		"root",
	)
	promotions, err := classifier.Process(failure)
	if err != nil {
		t.Fatal(err)
	}
	if len(promotions) != 0 {
		t.Fatalf("mapped trusted address produced promotions: %#v", promotions)
	}
}

func TestSSHEnforcesStateLimits(t *testing.T) {
	config := DefaultSSHConfig()
	config.MaxSources = 1
	config.MaxEventsPerSource = 2
	config.MaxTotalEvents = 2
	classifier, err := NewSSHClassifier(config)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 9, 10, 19, 0, 0, 0, time.UTC)
	first := netip.MustParseAddr("192.0.2.1")
	second := netip.MustParseAddr("192.0.2.2")

	for i := range 2 {
		if _, err := classifier.Process(sshFailure(i, start, first, "root")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := classifier.Process(sshFailure(2, start, first, "root")); err == nil {
		t.Fatal("classifier accepted more than the per-source event limit")
	}
	if _, err := classifier.Process(sshFailure(3, start, second, "root")); err == nil {
		t.Fatal("classifier accepted more than the source limit")
	}

	if err := classifier.Prune(start.Add(15 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := classifier.Process(sshFailure(4, start.Add(15*time.Minute), second, "root")); err != nil {
		t.Fatalf("classifier did not release pruned capacity: %v", err)
	}
}

func sshFailure(index int, observedAt time.Time, address netip.Addr, username string) SSHFailure {
	return SSHFailure{
		EventID:    fmt.Sprintf("event-%d", index),
		ObservedAt: observedAt,
		SourceIP:   address,
		Username:   username,
	}
}
