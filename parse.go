package main

import (
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// NitroAttestationPayload represents the structure of the attestation document.
type NitroAttestationPayload struct {
	ModuleID    string         `cbor:"module_id"`
	Digest      string         `cbor:"digest"`
	Timestamp   int64          `cbor:"timestamp"`
	PCRs        map[int][]byte `cbor:"pcrs"`
	Certificate []byte         `cbor:"certificate"`
	CABundle    [][]byte       `cbor:"cabundle"`
	PublicKey   []byte         `cbor:"public_key"`
	UserData    []byte         `cbor:"user_data"`
	Nonce       []byte         `cbor:"nonce"`
	// Raw holds the original attestation bytes.
	Raw []byte `cbor:"-"`
}

// ParseNitroAttestation parses raw (Base64‑decoded) attestation bytes into a NitroAttestationPayload.
func ParseNitroAttestation(raw []byte) (*NitroAttestationPayload, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty attestation raw bytes")
	}
	// Prepend 0xd2 if not present.
	if raw[0] != 0xd2 {
		raw = append([]byte{0xd2}, raw...)
	}

	var payload NitroAttestationPayload
	payload.Raw = raw

	decMode, err := cbor.DecOptions{}.DecMode()
	if err != nil {
		return nil, fmt.Errorf("failed to create CBOR decoder: %v", err)
	}

	var decoded interface{}
	if err := decMode.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("failed to decode CBOR: %v", err)
	}

	// If the attestation is COSE-wrapped (tag 18), extract the inner payload.
	if tag, ok := decoded.(cbor.Tag); ok {
		if tag.Number == 18 {
			coseArray, ok := tag.Content.([]interface{})
			if !ok || len(coseArray) < 3 {
				return nil, fmt.Errorf("invalid COSE structure")
			}
			payloadBytes, ok := coseArray[2].([]byte)
			if !ok {
				return nil, fmt.Errorf("COSE payload is not a byte array")
			}
			if err := decMode.Unmarshal(payloadBytes, &payload); err != nil {
				return nil, fmt.Errorf("failed to decode COSE payload: %v", err)
			}
		} else {
			return nil, fmt.Errorf("unsupported CBOR tag: %d", tag.Number)
		}
	} else {
		// Otherwise, re-marshal and unmarshal into our struct.
		temp, err := cbor.Marshal(decoded)
		if err != nil {
			return nil, fmt.Errorf("failed to re-marshal decoded CBOR: %v", err)
		}
		if err := decMode.Unmarshal(temp, &payload); err != nil {
			return nil, fmt.Errorf("failed to decode attestation payload: %v", err)
		}
	}

	// Basic field checks.
	if payload.ModuleID == "" {
		return nil, errors.New("module_id is empty")
	}
	if payload.Digest != "SHA384" {
		return nil, errors.New("digest type is not SHA384")
	}
	if payload.Timestamp == 0 {
		return nil, errors.New("timestamp is missing")
	}
	if len(payload.PCRs) < 1 || len(payload.PCRs) > 32 {
		return nil, errors.New("PCRs must have between 1 and 32 entries")
	}
	for key, val := range payload.PCRs {
		if key < 0 || key > 31 {
			return nil, fmt.Errorf("PCR key %d out of valid range", key)
		}
		if l := len(val); l != 32 && l != 48 && l != 64 {
			return nil, fmt.Errorf("PCR[%d] length invalid: got %d bytes", key, l)
		}
	}
	if len(payload.CABundle) < 1 {
		return nil, errors.New("CABundle must contain at least one certificate")
	}
	for _, ca := range payload.CABundle {
		if l := len(ca); l < 1 || l > 1024 {
			return nil, errors.New("CABundle certificate length out of range")
		}
	}
	if len(payload.PublicKey) > 0 && (len(payload.PublicKey) < 1 || len(payload.PublicKey) > 1024) {
		return nil, errors.New("PublicKey length out of range")
	}
	if len(payload.UserData) > 0 && (len(payload.UserData) < 1 || len(payload.UserData) > 512) {
		return nil, errors.New("UserData length out of range")
	}
	if len(payload.Nonce) > 0 && (len(payload.Nonce) < 1 || len(payload.Nonce) > 512) {
		return nil, errors.New("Nonce length out of range")
	}

	return &payload, nil
}