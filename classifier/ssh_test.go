package classifier

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"
)

func TestSSHPromotesEveryNonIgnoredAttempt(t *testing.T) {
	classifier, err := NewSSHClassifier(DefaultSSHConfig())
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 9, 10, 19, 0, 0, 0, time.UTC)
	address := netip.MustParseAddr("2001:db8::10")

	for i := range 3 {
		decision, err := classifier.Classify(sshFailure(i, start.Add(time.Duration(i)*time.Minute), address, "root"))
		if err != nil {
			t.Fatal(err)
		}
		if !decision.Eligible || !slices.Equal(decision.RuleIDs, []string{RuleSSHAllAttempts}) {
			t.Fatalf("attempt %d = %#v, want eligible with %s", i, decision, RuleSSHAllAttempts)
		}
	}
}

func TestSSHExclusionsAndTrustedNetworks(t *testing.T) {
	config := SSHConfig{
		ExcludedUsernames: []string{"deploy"},
		TrustedNetworks:   []netip.Prefix{netip.MustParsePrefix("2001:db8:1::/48")},
	}
	classifier, err := NewSSHClassifier(config)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 10, 19, 0, 0, 0, time.UTC)

	if decision, err := classifier.Classify(sshFailure(0, now, netip.MustParseAddr("192.0.2.1"), "deploy")); err != nil || decision.Eligible {
		t.Fatalf("excluded username = %#v, %v", decision, err)
	}
	if decision, err := classifier.Classify(sshFailure(1, now, netip.MustParseAddr("2001:db8:1::1"), "root")); err != nil || decision.Eligible {
		t.Fatalf("trusted network = %#v, %v", decision, err)
	}
	if decision, err := classifier.Classify(sshFailure(2, now, netip.MustParseAddr("192.0.2.2"), "root")); err != nil || !decision.Eligible {
		t.Fatalf("ordinary attempt = %#v, %v", decision, err)
	}
}

func TestSSHNormalizesMappedAddressBeforeTrustedNetworkCheck(t *testing.T) {
	config := SSHConfig{TrustedNetworks: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}
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
	decision, err := classifier.Classify(failure)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Eligible {
		t.Fatalf("mapped trusted address was eligible: %#v", decision)
	}
}

func TestSSHRejectsInvalidFailure(t *testing.T) {
	classifier, err := NewSSHClassifier(DefaultSSHConfig())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 10, 19, 0, 0, 0, time.UTC)
	if _, err := classifier.Classify(SSHFailure{ObservedAt: now, SourceIP: netip.MustParseAddr("192.0.2.1"), Username: "root"}); err == nil {
		t.Fatal("classifier accepted an empty event ID")
	}
	if _, err := classifier.Classify(SSHFailure{EventID: "e", ObservedAt: now, SourceIP: netip.MustParseAddr("192.0.2.1")}); err == nil {
		t.Fatal("classifier accepted an empty username")
	}
	if _, err := classifier.Classify(SSHFailure{EventID: "e", ObservedAt: now.Local(), SourceIP: netip.MustParseAddr("192.0.2.1"), Username: "root"}); err == nil {
		t.Fatal("classifier accepted a non-UTC observation time")
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