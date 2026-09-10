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

func (p *Processor) RestoreSSH(ctx context.Context, since time.Time, limit int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.poisoned != nil {
		return fmt.Errorf("%w: %v", ErrPoisoned, p.poisoned)
	}
	failures, err := p.store.SSHFailuresSince(ctx, since, limit)
	if err != nil {
		p.poisoned = err
		return err
	}
	for _, failure := range failures {
		if _, err := p.ssh.Process(failure); err != nil {
			p.poisoned = err
			return fmt.Errorf("restore SSH classifier state: %w", err)
		}
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
	ignored, err := p.ssh.ShouldIgnore(failure)
	if err != nil {
		return err
	}
	if ignored {
		if err := p.store.CommitCursor(ctx, adapterID, observation.Cursor); err != nil {
			p.poisoned = err
			return err
		}
		return nil
	}
	promotions, err := p.ssh.Process(failure)
	if err != nil {
		return err
	}
	updates := make([]store.PromotionUpdate, 0, len(promotions))
	for _, promotion := range promotions {
		updates = append(updates, store.PromotionUpdate{
			EventID: promotion.Observation.EventID,
			RuleIDs: promotion.RuleIDs,
		})
	}
	if _, err := p.store.CommitObservation(
		ctx,
		adapterID,
		store.ClassifiedObservation{Observation: observation},
		updates...,
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
