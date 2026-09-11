package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/gasserp/probing/protocol"
)

func TestCommitObservationAdvancesCursorAtomically(t *testing.T) {
	ctx := context.Background()
	state := openTestStore(t)
	observation := testSSHObservation("event-1", "cursor-1", "root", "2026-09-10T19:00:00Z")

	inserted, err := state.CommitObservation(ctx, "openssh", ClassifiedObservation{Observation: observation})
	if err != nil {
		t.Fatal(err)
	}
	if !inserted {
		t.Fatal("new SSH observation was not inserted")
	}

	observation.Cursor = "cursor-2"
	inserted, err = state.CommitObservation(ctx, "openssh", ClassifiedObservation{Observation: observation})
	if err != nil {
		t.Fatalf("idempotent replay failed: %v", err)
	}
	if inserted {
		t.Fatal("idempotent replay inserted a second observation")
	}
	cursor, found, err := state.Cursor(ctx, "openssh")
	if err != nil || !found || cursor != "cursor-2" {
		t.Fatalf("cursor after replay = %q, %v, %v", cursor, found, err)
	}

	observation.Cursor = "cursor-3"
	observation.SSH.Username = "admin"
	if _, err := state.CommitObservation(ctx, "openssh", ClassifiedObservation{Observation: observation}); !errors.Is(err, ErrEventIDCollision) {
		t.Fatalf("conflicting event error = %v", err)
	}
	cursor, found, err = state.Cursor(ctx, "openssh")
	if err != nil || !found || cursor != "cursor-2" {
		t.Fatalf("collision advanced cursor to %q, %v, %v", cursor, found, err)
	}

	ignoredHTTP := protocol.Observation{
		SchemaVersion: protocol.ObservationSchemaVersion,
		EventID:       "http-1",
		Cursor:        "line-1",
		Kind:          protocol.ObservationHTTPRequest,
		ObservedAt:    "2026-09-10T19:01:00Z",
		SourceIP:      "2001:db8::10",
		HTTP: &protocol.HTTPObservation{
			RequestTarget: "/ordinary/path?private=value",
			Status:        404,
		},
	}
	inserted, err = state.CommitObservation(ctx, "nginx", ClassifiedObservation{Observation: ignoredHTTP})
	if err != nil {
		t.Fatal(err)
	}
	if inserted {
		t.Fatal("unpromoted HTTP observation was persisted")
	}
	var count int
	if err := state.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM observations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("stored observation count = %d, want 1", count)
	}

	promotedHTTP := ignoredHTTP
	promotedHTTP.EventID = "http-2"
	promotedHTTP.Cursor = "line-2"
	promotedHTTP.HTTP.RequestTarget = "/../etc/passwd?token=first"
	classified := ClassifiedObservation{
		Observation: promotedHTTP,
		Promoted:    true,
		PublicPath:  "/../etc/passwd",
		RuleIDs:     []string{"http/path-traversal-v1"},
	}
	if _, err := state.CommitObservation(ctx, "nginx", classified); err != nil {
		t.Fatal(err)
	}
	classified.Observation.Cursor = "line-3"
	classified.Observation.HTTP.RequestTarget = "/../etc/passwd?token=second"
	inserted, err = state.CommitObservation(ctx, "nginx", classified)
	if err != nil {
		t.Fatalf("discarded query changed collision identity: %v", err)
	}
	if inserted {
		t.Fatal("query-only replay inserted a second HTTP observation")
	}
}

func TestApplyPromotionsMergesRulesWithoutDuplicatingObservation(t *testing.T) {
	ctx := context.Background()
	state := openTestStore(t)
	observation := testSSHObservation("event-1", "cursor-1", "root", "2026-09-10T19:00:00Z")
	if _, err := state.CommitObservation(ctx, "openssh", ClassifiedObservation{Observation: observation}, PromotionUpdate{
		EventID: "event-1",
		RuleIDs: []string{"ssh/distinct-usernames-v1"},
	}); err != nil {
		t.Fatal(err)
	}

	second := testSSHObservation("event-2", "cursor-2", "admin", "2026-09-10T19:01:00Z")
	if _, err := state.CommitObservation(ctx, "openssh", ClassifiedObservation{Observation: second},
		PromotionUpdate{
			EventID: "event-1",
			RuleIDs: []string{"ssh/pair-threshold-v1"},
		},
		PromotionUpdate{
			EventID: "event-2",
			RuleIDs: []string{"ssh/distinct-usernames-v1"},
		},
	); err != nil {
		t.Fatal(err)
	}

	var promoted int
	var rulesJSON string
	if err := state.db.QueryRowContext(ctx, `
		SELECT promoted, rule_ids FROM observations WHERE event_id = 'event-1'
	`).Scan(&promoted, &rulesJSON); err != nil {
		t.Fatal(err)
	}
	var rules []string
	if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
		t.Fatal(err)
	}
	if promoted != 1 || !slices.Equal(rules, []string{"ssh/distinct-usernames-v1", "ssh/pair-threshold-v1"}) {
		t.Fatalf("stored promotion = %d, %v", promoted, rules)
	}
}

func TestPromotionRuleUnionIsBoundedAtomically(t *testing.T) {
	ctx := context.Background()
	state := openTestStore(t)
	first := testSSHObservation("event-1", "cursor-1", "root", "2026-09-10T19:00:00Z")
	rules := make([]string, protocol.MaxRuleIDs)
	for i := range rules {
		rules[i] = fmt.Sprintf("test/rule-%02d", i)
	}
	if _, err := state.CommitObservation(ctx, "openssh", ClassifiedObservation{Observation: first}, PromotionUpdate{
		EventID: first.EventID,
		RuleIDs: rules,
	}); err != nil {
		t.Fatal(err)
	}

	second := testSSHObservation("event-2", "cursor-2", "admin", "2026-09-10T19:01:00Z")
	if _, err := state.CommitObservation(ctx, "openssh", ClassifiedObservation{Observation: second}, PromotionUpdate{
		EventID: first.EventID,
		RuleIDs: []string{"test/rule-extra"},
	}); err == nil {
		t.Fatal("promotion union exceeded the protocol rule limit")
	}
	cursor, found, err := state.Cursor(ctx, "openssh")
	if err != nil || !found || cursor != "cursor-1" {
		t.Fatalf("failed rule union advanced cursor to %q, %v, %v", cursor, found, err)
	}
	var count int
	if err := state.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM observations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("failed atomic transaction left %d observations", count)
	}
}

func TestPendingBatchIsImmutableAcrossRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	state, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}

	ssh := testSSHObservation("ssh-1", "cursor-1", "root", "2026-09-10T19:05:00Z")
	if _, err := state.CommitObservation(ctx, "openssh", ClassifiedObservation{Observation: ssh}, PromotionUpdate{
		EventID: "ssh-1",
		RuleIDs: []string{"ssh/pair-threshold-v1"},
	}); err != nil {
		t.Fatal(err)
	}

	http := protocol.Observation{
		SchemaVersion: protocol.ObservationSchemaVersion,
		EventID:       "http-1",
		Cursor:        "line-1",
		Kind:          protocol.ObservationHTTPRequest,
		ObservedAt:    "2026-09-10T19:10:00Z",
		SourceIP:      "192.0.2.20",
		HTTP: &protocol.HTTPObservation{
			RequestTarget: "/public/../etc/passwd?secret=discarded",
			Status:        404,
		},
	}
	if _, err := state.CommitObservation(ctx, "nginx", ClassifiedObservation{
		Observation: http,
		Promoted:    true,
		PublicPath:  "/public/../etc/passwd",
		RuleIDs:     []string{"http/path-traversal-v1", "http/sensitive-file-v1"},
	}); err != nil {
		t.Fatal(err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := BatchConfig{
		SourceID:          "sensor-one",
		SourceEpoch:       "5d6079de-20e0-4d4b-b955-40eac8f14df8",
		ClassifierVersion: "classifier-v1",
		KeyID:             "key-1",
		PrivateKey:        privateKey,
	}
	first, err := state.CreatePendingBatch(
		ctx,
		config,
		time.Date(2026, 9, 10, 20, 0, 0, 0, time.UTC),
		time.Date(2026, 9, 10, 19, 30, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	if first.Sequence != "0" {
		t.Fatalf("first sequence = %q, want 0", first.Sequence)
	}
	decoded, err := protocol.DecodeSignedBatch(first.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.VerifyBatch(decoded, publicKey); err != nil {
		t.Fatal(err)
	}
	if decoded.Payload.Records[0].Kind != protocol.ObservationHTTPRequest ||
		decoded.Payload.Records[0].Path != "/public/../etc/passwd" {
		t.Fatalf("HTTP record was not sanitized and sorted: %#v", decoded.Payload.Records[0])
	}

	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	state, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()

	pending, found, err := state.NextPendingBatch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !found || !bytes.Equal(pending.Envelope, first.Envelope) {
		t.Fatal("pending batch bytes changed after restart")
	}
	blockedObservation := testSSHObservation("ssh-blocked", "cursor-blocked", "guest", "2026-09-10T20:01:00Z")
	if _, err := state.CommitObservation(ctx, "openssh", ClassifiedObservation{Observation: blockedObservation},
		PromotionUpdate{
			EventID: "ssh-1",
			RuleIDs: []string{"ssh/distinct-usernames-v1"},
		},
	); err == nil {
		t.Fatal("promotion changed an observation in an immutable batch")
	}
	cursor, _, err := state.Cursor(ctx, "openssh")
	if err != nil {
		t.Fatal(err)
	}
	if cursor != "cursor-1" {
		t.Fatalf("failed atomic promotion advanced cursor to %q", cursor)
	}
	if err := state.MarkBatchPublished(
		ctx,
		"0",
		first.PayloadHash,
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	); err != nil {
		t.Fatal(err)
	}
	_, found, err = state.NextPendingBatch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Fatal("published batch remained pending")
	}

	secondObservation := testSSHObservation("ssh-2", "cursor-2", "admin", "2026-09-10T20:05:00Z")
	if _, err := state.CommitObservation(ctx, "openssh", ClassifiedObservation{
		Observation: secondObservation,
	}, PromotionUpdate{
		EventID: "ssh-2",
		RuleIDs: []string{"ssh/pair-threshold-v1"},
	}); err != nil {
		t.Fatal(err)
	}
	second, err := state.CreatePendingBatch(
		ctx,
		config,
		time.Date(2026, 9, 10, 21, 0, 0, 0, time.UTC),
		time.Date(2026, 9, 10, 20, 30, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err = protocol.DecodeSignedBatch(second.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	if second.Sequence != "1" || decoded.Payload.PreviousBatchHash != first.PayloadHash {
		t.Fatalf("second batch chain = sequence %q, previous %q", second.Sequence, decoded.Payload.PreviousBatchHash)
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	state, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := state.Close(); err != nil {
			t.Errorf("close state database: %v", err)
		}
	})
	return state
}

func testSSHObservation(eventID, cursor, username, observedAt string) protocol.Observation {
	return protocol.Observation{
		SchemaVersion: protocol.ObservationSchemaVersion,
		EventID:       eventID,
		Cursor:        cursor,
		Kind:          protocol.ObservationSSHAuthFailure,
		ObservedAt:    observedAt,
		SourceIP:      "2001:db8::10",
		SSH:           &protocol.SSHObservation{Username: username},
	}
}
