package attestation

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	cbor "github.com/fxamacker/cbor/v2"
)

// https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
var AWSNitroEnclavesRootCertFingerprint = hexutil.MustDecode("0x641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b")

// NSMAttestationDoc represents the structure of the attestation document.
//
// Can be verified with 'Verify' method
type NSMAttestationDoc struct {
	ModuleID    string
	Timestamp   time.Time
	Digest      string
	PCRs        map[int][]byte
	Certificate *x509.Certificate
	CABundle    []*x509.Certificate
	PublicKey   []byte
	UserData    []byte
	Nonce       []byte

	Signature []byte

	// Raw holds the original attestation bytes with signature (COSE Sign1).
	Raw []byte
	// Payload holds CBOR encoded attestation doc.
	Payload []byte
}

// ParseNSMAttestationDoc parses raw (Base64‑decoded) attestation bytes into a NSMAttestationDoc.
func ParseNSMAttestationDoc(raw []byte) (*NSMAttestationDoc, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty attestation raw bytes")
	}
	// Prepend 0xd2 if not present.
	if raw[0] != 0xd2 {
		raw = append([]byte{0xd2}, raw...)
	}

	var coseSign1Msg coseSign1
	err := cbor.Unmarshal(raw, &coseSign1Msg)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal COSE Sign1: %w", err)
	}

	var doc nsmAttestationDoc
	err = cbor.Unmarshal(coseSign1Msg.Payload, &doc)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal NSM attestation document: %w", err)
	}

	var protected struct {
		Alg int `cbor:"1,keyasint"`
	}
	err = cbor.Unmarshal(coseSign1Msg.Protected, &protected)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal protected(COSE): %w", err)
	}
	if protected.Alg != -35 {
		return nil, fmt.Errorf("invalid signing algorithm, should be ECDS SHA-384")
	}

	// Basic field checks.
	if doc.ModuleID == "" {
		return nil, errors.New("module_id is empty")
	}
	if doc.Digest != "SHA384" {
		return nil, errors.New("digest type is not SHA384")
	}
	if doc.Timestamp == 0 {
		return nil, errors.New("timestamp is missing")
	}
	if len(doc.PCRs) < 1 || len(doc.PCRs) > 32 {
		return nil, errors.New("PCRs must have between 1 and 32 entries")
	}
	for key, val := range doc.PCRs {
		if key < 0 || key > 31 {
			return nil, fmt.Errorf("PCR key %d out of valid range", key)
		}
		if l := len(val); l != 32 && l != 48 && l != 64 {
			return nil, fmt.Errorf("PCR[%d] length invalid: got %d bytes", key, l)
		}
	}
	if len(doc.CABundle) < 1 {
		return nil, errors.New("CABundle must contain at least one certificate")
	}
	for _, ca := range doc.CABundle {
		if l := len(ca); l < 1 || l > 1024 {
			return nil, errors.New("CABundle certificate length out of range")
		}
	}
	if len(doc.PublicKey) > 0 && (len(doc.PublicKey) < 1 || len(doc.PublicKey) > 1024) {
		return nil, errors.New("PublicKey length out of range")
	}
	if len(doc.UserData) > 0 && (len(doc.UserData) < 1 || len(doc.UserData) > 512) {
		return nil, errors.New("UserData length out of range")
	}
	if len(doc.Nonce) > 0 && (len(doc.Nonce) < 1 || len(doc.Nonce) > 512) {
		return nil, errors.New("Nonce length out of range")
	}

	certificate, err := x509.ParseCertificate(doc.Certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	caBundle := make([]*x509.Certificate, len(doc.CABundle))
	for i, rawCert := range doc.CABundle {
		caBundle[i], err = x509.ParseCertificate(rawCert)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ca bundle cert #%d: %w", i, err)
		}
	}

	return &NSMAttestationDoc{
		ModuleID:    doc.ModuleID,
		Timestamp:   time.Unix(0, int64(time.Millisecond)*doc.Timestamp),
		Digest:      doc.Digest,
		PCRs:        doc.PCRs,
		Certificate: certificate,
		CABundle:    caBundle,
		PublicKey:   doc.PublicKey,
		UserData:    doc.UserData,
		Nonce:       doc.Nonce,

		Signature: coseSign1Msg.Signature,
		Raw:       raw,
		Payload:   coseSign1Msg.Payload,
	}, nil
}

// Signature and certificate chain verification
func (ad *NSMAttestationDoc) Verify() error {
	if err := ad.verifyCertChain(); err != nil {
		return err
	}
	return ad.verifySignature()
}

func (ad *NSMAttestationDoc) verifySignature() error {
	// https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
	// {1: -35}
	protectedHeaders := []byte{161, 1, 56, 34}

	coseSign1ToSign := []any{
		"Signature1",
		protectedHeaders,
		[]byte{},
		ad.Payload,
	}

	dataToSign, err := cbor.Marshal(coseSign1ToSign)
	if err != nil {
		return fmt.Errorf("failed to marshal COSE Sign1: %w", err)
	}

	sum384 := crypto.SHA384.New()
	sum384.Write(dataToSign)

	publicKey, ok := ad.Certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("invalid public key")
	}
	if len(ad.Signature) != 96 {
		return fmt.Errorf("invalid signature length")
	}

	r := new(big.Int).SetBytes(ad.Signature[:48])
	s := new(big.Int).SetBytes(ad.Signature[48:])

	if !ecdsa.Verify(publicKey, sum384.Sum(nil), r, s) {
		return fmt.Errorf("invalid ecdsa signature")
	}

	return nil
}

func (ad *NSMAttestationDoc) verifyCertChain() error {
	if len(ad.CABundle) < 1 {
		return fmt.Errorf("CA bundle don't have certs")
	}

	// verify root cert
	rootCertHash := sha256.Sum256(ad.CABundle[0].Raw)
	if !bytes.Equal(rootCertHash[:], AWSNitroEnclavesRootCertFingerprint) {
		return fmt.Errorf("root certificate fingerprint does not match")
	}

	// verify cert chain
	certCount := len(ad.CABundle)
	for i := certCount - 1; i > 0; i-- {
		if err := ad.CABundle[i].CheckSignatureFrom(ad.CABundle[i-1]); err != nil {
			return fmt.Errorf("failed to verify certificate chain: %w", err)
		}
	}

	// verify NSM cert
	if err := ad.Certificate.CheckSignatureFrom(ad.CABundle[certCount-1]); err != nil {
		return fmt.Errorf("failed to verify NSM certificate: %w", err)
	}

	return nil
}

type nsmAttestationDoc struct {
	ModuleID    string         `cbor:"module_id"`
	Digest      string         `cbor:"digest"`
	Timestamp   int64          `cbor:"timestamp"`
	PCRs        map[int][]byte `cbor:"pcrs"`
	Certificate []byte         `cbor:"certificate"`
	CABundle    [][]byte       `cbor:"cabundle"`
	PublicKey   []byte         `cbor:"public_key"`
	UserData    []byte         `cbor:"user_data"`
	Nonce       []byte         `cbor:"nonce"`
}

type coseSign1 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected cbor.RawMessage
	Payload     []byte
	Signature   []byte
}
