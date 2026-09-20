package core

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/gasserp/probing/classifier"
	"github.com/gasserp/probing/protocol"
	"github.com/gasserp/probing/store"
)

var ErrPoisoned = errors.New("processor state requires restart")

type Processor struct {
	mu       sync.Mutex
	store    *store.Store
	ssh      *classifier.SSHClassifier
	http     *classifier.HTTPClassifier
	poisoned error
}

func NewProcessor(
	state *store.Store,
	ssh *classifier.SSHClassifier,
	http *classifier.HTTPClassifier,
) (*Processor, error) {
	if state == nil || ssh == nil || http == nil {
		return nil, errors.New("store and classifiers are required")
	}
	return &Processor{store: state, ssh: ssh, http: http}, nil
}

func (p *Processor) Process(
	ctx context.Context,
	adapterID string,
	observation protocol.Observation,
) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.poisoned != nil {
		return fmt.Errorf("%w: %v", ErrPoisoned, p.poisoned)
	}
	if err := protocol.ValidateObservation(observation); err != nil {
		return err
	}

	switch observation.Kind {
	case protocol.ObservationSSHAuthFailure:
		return p.processSSH(ctx, adapterID, observation)
	case protocol.ObservationHTTPRequest:
		return p.processHTTP(ctx, adapterID, observation)
	default:
		return fmt.Errorf("unsupported observation kind %q", observation.Kind)
	}
}

func (p *Processor) Checkpoint(ctx context.Context, adapterID, cursor string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.poisoned != nil {
		return fmt.Errorf("%w: %v", ErrPoisoned, p.poisoned)
	}
	if err := p.store.CommitCursor(ctx, adapterID, cursor); err != nil {
		p.poisoned = err
		return err
	}
	return nil
}

func (p *Processor) processSSH(
	ctx context.Context,
	adapterID string,
	observation protocol.Observation,
) error {
	stored, err := p.store.HasSSHObservation(ctx, observation)
	if err != nil {
		p.poisoned = err
		return err
	}
	if stored {
		if err := p.store.CommitCursor(ctx, adapterID, observation.Cursor); err != nil {
			p.poisoned = err
			return err
		}
		return nil
	}
	observedAt, _ := time.Parse(time.RFC3339Nano, observation.ObservedAt)
	sourceIP, _ := netip.ParseAddr(observation.SourceIP)
	failure := classifier.SSHFailure{
		EventID:    observation.EventID,
		ObservedAt: observedAt,
		SourceIP:   sourceIP,
		Username:   observation.SSH.Username,
	}
	decision, err := p.ssh.Classify(failure)
	if err != nil {
		return err
	}
	if !decision.Eligible {
		if err := p.store.CommitCursor(ctx, adapterID, observation.Cursor); err != nil {
			p.poisoned = err
			return err
		}
		return nil
	}
	if _, err := p.store.CommitObservation(
		ctx,
		adapterID,
		store.ClassifiedObservation{Observation: observation},
		store.PromotionUpdate{EventID: observation.EventID, RuleIDs: decision.RuleIDs},
	); err != nil {
		p.poisoned = err
		return err
	}
	return nil
}

func (p *Processor) processHTTP(
	ctx context.Context,
	adapterID string,
	observation protocol.Observation,
) error {
	decision, err := p.http.Classify(classifier.HTTPRequest{
		EventID:       observation.EventID,
		RequestTarget: observation.HTTP.RequestTarget,
		Status:        observation.HTTP.Status,
	})
	if err != nil {
		return err
	}
	input := store.ClassifiedObservation{Observation: observation}
	if decision.Eligible {
		input.Promoted = true
		input.PublicPath = decision.Path
		input.RuleIDs = decision.RuleIDs
	}
	if _, err := p.store.CommitObservation(ctx, adapterID, input); err != nil {
		p.poisoned = err
		return err
	}
	return nil
}
