package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gasserp/probing/protocol"
	"github.com/gasserp/probing/publication"
	"github.com/gasserp/probing/store"
)

const (
	publishPollInterval = 15 * time.Second
	maxPrivateKeyBytes  = 4_096
	maxEpochBytes       = 64
)

type batchPublisher struct {
	state             *store.Store
	config            store.BatchConfig
	outboxDir         string
	watermarkLag      time.Duration
	lastCompletedHour time.Time
	now               func() time.Time
}

func newBatchPublisher(state *store.Store, config publicationConfig, watermarkLag time.Duration) (*batchPublisher, error) {
	batchConfig, err := config.batchConfig()
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(config.OutboxDirectory)
	if err != nil {
		return nil, fmt.Errorf("inspect outbox directory: %w", err)
	}
	if !info.IsDir() {
		return nil, errors.New("outbox path is not a directory")
	}
	return &batchPublisher{
		state:        state,
		config:       batchConfig,
		outboxDir:    config.OutboxDirectory,
		watermarkLag: watermarkLag,
		now:          time.Now,
	}, nil
}

func (p *batchPublisher) Run(ctx context.Context) error {
	if err := p.pump(ctx); err != nil {
		return err
	}
	ticker := time.NewTicker(publishPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := p.pump(ctx); err != nil {
				return err
			}
		}
	}
}

func (p *batchPublisher) pump(ctx context.Context) error {
	if err := p.reconcileReceipts(ctx); err != nil {
		return err
	}
	for {
		pending, found, err := p.state.NextPendingBatch(ctx)
		if err != nil {
			return err
		}
		if found {
			acked, err := p.exposeOrAcknowledge(ctx, pending)
			if err != nil {
				return err
			}
			if !acked {
				return nil
			}
			continue
		}

		hour := p.now().UTC().Truncate(time.Hour)
		if !p.lastCompletedHour.IsZero() && !hour.After(p.lastCompletedHour) {
			return nil
		}
		_, err = p.state.CreatePendingBatch(
			ctx,
			p.config,
			hour,
			hour.Add(-p.watermarkLag),
		)
		if errors.Is(err, store.ErrNoPromotedObservations) {
			p.lastCompletedHour = hour
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (p *batchPublisher) exposeOrAcknowledge(ctx context.Context, pending store.PendingBatch) (bool, error) {
	envelope, err := publication.ValidateEnvelope(pending.Envelope)
	if err != nil {
		return false, fmt.Errorf("validate stored envelope: %w", err)
	}
	if envelope.Batch.Payload.Sequence != pending.Sequence || envelope.PayloadHash != pending.PayloadHash {
		return false, errors.New("stored pending batch identity does not match its envelope")
	}
	envelopePath := filepath.Join(p.outboxDir, envelope.FileName)
	existing, err := readBoundedFile(envelopePath, protocol.MaxEncodedEnvelopeBytes)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("read outbox envelope: %w", err)
	}
	if errors.Is(err, os.ErrNotExist) {
		if err := publication.AtomicWrite(envelopePath, pending.Envelope, 0o640); err != nil {
			return false, err
		}
	} else if !bytes.Equal(existing, pending.Envelope) {
		return false, errors.New("outbox envelope conflicts with immutable stored bytes")
	}

	receiptPath := filepath.Join(p.outboxDir, publication.ReceiptFileName(envelope.FileName))
	receiptBytes, err := readBoundedFile(receiptPath, publication.MaxReceiptBytes)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read uploader receipt: %w", err)
	}
	receipt, err := publication.DecodeReceipt(receiptBytes)
	if err != nil {
		return false, err
	}
	if receipt.SourceID != envelope.Batch.Payload.SourceID ||
		receipt.SourceEpoch != envelope.Batch.Payload.SourceEpoch ||
		receipt.Sequence != pending.Sequence ||
		receipt.PayloadHash != pending.PayloadHash ||
		receipt.EnvelopeSHA256 != envelope.EnvelopeSHA256 ||
		receipt.BlobName != envelope.BlobName {
		return false, errors.New("uploader receipt does not match the pending envelope")
	}
	if err := p.acknowledge(
		ctx,
		envelopePath,
		receiptPath,
		envelope,
		receiptBytes,
		receipt,
	); err != nil {
		return false, err
	}
	return true, nil
}

func (p *batchPublisher) reconcileReceipts(ctx context.Context) error {
	entries, err := os.ReadDir(p.outboxDir)
	if err != nil {
		return fmt.Errorf("read outbox directory: %w", err)
	}
	if len(entries) > publication.MaxOutboxFiles {
		return fmt.Errorf("outbox contains more than %d files", publication.MaxOutboxFiles)
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".receipt.json") {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("outbox receipt must not be a symbolic link")
		}
		receiptPath := filepath.Join(p.outboxDir, entry.Name())
		receiptBytes, err := readBoundedFile(receiptPath, publication.MaxReceiptBytes)
		if err != nil {
			return fmt.Errorf("read uploader receipt: %w", err)
		}
		receipt, err := publication.DecodeReceipt(receiptBytes)
		if err != nil {
			return err
		}
		envelopeName := strings.TrimSuffix(entry.Name(), ".receipt.json") + ".json"
		envelopePath := filepath.Join(p.outboxDir, envelopeName)
		envelopeBytes, err := readBoundedFile(envelopePath, protocol.MaxEncodedEnvelopeBytes)
		if err != nil {
			return fmt.Errorf("read acknowledged envelope: %w", err)
		}
		envelope, err := publication.ValidateEnvelope(envelopeBytes)
		if err != nil {
			return err
		}
		if envelope.FileName != envelopeName {
			return errors.New("acknowledged envelope file name is not deterministic")
		}
		if err := p.acknowledge(
			ctx,
			envelopePath,
			receiptPath,
			envelope,
			receiptBytes,
			receipt,
		); err != nil {
			return err
		}
	}
	return nil
}

func (p *batchPublisher) acknowledge(
	ctx context.Context,
	envelopePath, receiptPath string,
	envelope publication.Envelope,
	receiptBytes []byte,
	receipt publication.Receipt,
) error {
	if receipt.SourceID != envelope.Batch.Payload.SourceID ||
		receipt.SourceEpoch != envelope.Batch.Payload.SourceEpoch ||
		receipt.Sequence != envelope.Batch.Payload.Sequence ||
		receipt.PayloadHash != envelope.PayloadHash ||
		receipt.EnvelopeSHA256 != envelope.EnvelopeSHA256 ||
		receipt.BlobName != envelope.BlobName {
		return errors.New("uploader receipt does not match the pending envelope")
	}
	receiptHash := sha256.Sum256(receiptBytes)
	if err := p.state.MarkBatchPublished(
		ctx,
		receipt.Sequence,
		receipt.PayloadHash,
		hex.EncodeToString(receiptHash[:]),
	); err != nil {
		return err
	}
	if err := os.Remove(receiptPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove acknowledged receipt: %w", err)
	}
	if err := os.Remove(envelopePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove acknowledged envelope: %w", err)
	}
	if err := publication.SyncDirectory(p.outboxDir); err != nil {
		return err
	}
	return nil
}

func (c publicationConfig) batchConfig() (store.BatchConfig, error) {
	epochData, err := readBoundedFile(c.SourceEpochPath, maxEpochBytes)
	if err != nil {
		return store.BatchConfig{}, fmt.Errorf("read source epoch: %w", err)
	}
	epoch := strings.TrimSpace(string(epochData))
	if err := protocol.ValidateSourceIdentity(c.SourceID, epoch); err != nil {
		return store.BatchConfig{}, err
	}
	if err := protocol.ValidateKeyID(c.KeyID); err != nil {
		return store.BatchConfig{}, err
	}
	keyData, err := readPrivateKey(c.PrivateKeyPath)
	if err != nil {
		return store.BatchConfig{}, err
	}
	block, rest := pem.Decode(keyData)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return store.BatchConfig{}, errors.New("private key must be one PKCS#8 PEM PRIVATE KEY block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return store.BatchConfig{}, fmt.Errorf("parse private key: %w", err)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return store.BatchConfig{}, errors.New("private key is not Ed25519")
	}
	return store.BatchConfig{
		SourceID:          c.SourceID,
		SourceEpoch:       epoch,
		ClassifierVersion: c.ClassifierVersion,
		KeyID:             c.KeyID,
		PrivateKey:        privateKey,
	}, nil
}

func readPrivateKey(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect private key: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, errors.New("private key must be a regular file with mode 0600")
	}
	data, err := readBoundedFile(path, maxPrivateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	return data, nil
}

func readBoundedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || int64(len(data)) > limit {
		return nil, errors.New("file is empty or exceeds its size limit")
	}
	return data, nil
}
