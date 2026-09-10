package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
)

const signingDomain = "probing-batch-v1\x00"

func CanonicalPayload(payload BatchPayload) ([]byte, error) {
	if err := ValidateBatchPayload(payload); err != nil {
		return nil, err
	}
	return canonicalPayload(payload)
}

func canonicalPayload(payload BatchPayload) ([]byte, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal batch payload: %w", err)
	}

	canonical, err := jcs.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("canonicalize batch payload: %w", err)
	}
	return canonical, nil
}

func SigningBytes(payload BatchPayload) ([]byte, error) {
	if err := ValidateBatchPayload(payload); err != nil {
		return nil, err
	}
	return signingBytesValidated(payload)
}

func PayloadHash(payload BatchPayload) (string, error) {
	message, err := SigningBytes(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(message)
	return hex.EncodeToString(sum[:]), nil
}

func SignBatch(payload BatchPayload, keyID string, privateKey ed25519.PrivateKey) (SignedBatch, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedBatch{}, errors.New("invalid Ed25519 private key")
	}
	if !validBoundedText(keyID, MaxKeyIDBytes) {
		return SignedBatch{}, errors.New("key ID is invalid")
	}
	if err := ValidateBatchPayload(payload); err != nil {
		return SignedBatch{}, err
	}

	message, err := signingBytesValidated(payload)
	if err != nil {
		return SignedBatch{}, err
	}
	signature := ed25519.Sign(privateKey, message)

	return SignedBatch{
		Payload: payload,
		Signature: Signature{
			Algorithm: "Ed25519",
			KeyID:     keyID,
			Value:     base64.RawURLEncoding.EncodeToString(signature),
		},
	}, nil
}

func VerifyBatch(batch SignedBatch, publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 public key")
	}
	if batch.Signature.Algorithm != "Ed25519" {
		return fmt.Errorf("unsupported signature algorithm %q", batch.Signature.Algorithm)
	}
	if !validBoundedText(batch.Signature.KeyID, MaxKeyIDBytes) {
		return errors.New("signature key ID is invalid")
	}
	if err := ValidateBatchPayload(batch.Payload); err != nil {
		return err
	}

	signature, err := base64.RawURLEncoding.DecodeString(batch.Signature.Value)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return errors.New("invalid Ed25519 signature size")
	}

	message, err := signingBytesValidated(batch.Payload)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, message, signature) {
		return errors.New("signature verification failed")
	}
	return nil
}

func DecodeSignedBatch(data []byte) (SignedBatch, error) {
	if len(data) == 0 || len(data) > MaxEncodedEnvelopeBytes {
		return SignedBatch{}, fmt.Errorf("signed batch must contain between 1 and %d bytes", MaxEncodedEnvelopeBytes)
	}
	if !utf8.Valid(data) {
		return SignedBatch{}, errors.New("signed batch is not valid UTF-8")
	}

	var batch SignedBatch
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&batch); err != nil {
		return SignedBatch{}, fmt.Errorf("decode signed batch: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return SignedBatch{}, errors.New("signed batch contains trailing JSON")
	}
	if err := ValidateBatchPayload(batch.Payload); err != nil {
		return SignedBatch{}, err
	}
	return batch, nil
}

func signingBytesValidated(payload BatchPayload) ([]byte, error) {
	canonical, err := canonicalPayload(payload)
	if err != nil {
		return nil, err
	}
	message := make([]byte, 0, len(signingDomain)+len(canonical))
	message = append(message, signingDomain...)
	message = append(message, canonical...)
	return message, nil
}
