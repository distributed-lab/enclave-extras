package kmshelpers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"golang.org/x/crypto/cryptobyte"
)

const ecPrivKeyVersion = 1

var (
	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidNamedCurveS256 = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
)

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// Wrapped x509.ParsePKIXPublicKey() with support secp256k1
func ParseSubjectPublicKeyInfo(derBytes []byte) (any, error) {
	var pubKeyInfo publicKeyInfo
	if _, err := asn1.Unmarshal(derBytes, &pubKeyInfo); err != nil {
		return nil, err
	}

	if !pubKeyInfo.Algorithm.Algorithm.Equal(oidPublicKeyECDSA) {
		return x509.ParsePKIXPublicKey(derBytes)
	}

	params := pubKeyInfo.Algorithm.Parameters
	publicKeyBytes := cryptobyte.String(pubKeyInfo.PublicKey.RightAlign())

	paramsDer := cryptobyte.String(params.FullBytes)
	namedCurveOID := new(asn1.ObjectIdentifier)
	if !paramsDer.ReadASN1ObjectIdentifier(namedCurveOID) {
		return nil, fmt.Errorf("x509: invalid ECDSA parameters")
	}

	if !namedCurveOID.Equal(oidNamedCurveS256) {
		return x509.ParsePKIXPublicKey(derBytes)
	}

	x, y := elliptic.Unmarshal(secp256k1.S256(), publicKeyBytes)
	if x == nil {
		return nil, fmt.Errorf("x509: failed to unmarshal elliptic curve point")
	}

	return &ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     x,
		Y:     y,
	}, nil
}

// Wrapped x509.ParsePKCS8PrivateKey() with support secp256k1
func ParsePKCS8PrivateKey(derBytes []byte) (key any, err error) {
	var pkcs8PrivKey pkcs8
	if _, err := asn1.Unmarshal(derBytes, &pkcs8PrivKey); err != nil {
		return nil, err
	}

	if !pkcs8PrivKey.Algo.Algorithm.Equal(oidPublicKeyECDSA) {
		return x509.ParsePKCS8PrivateKey(derBytes)
	}

	paramsDer := pkcs8PrivKey.Algo.Parameters.FullBytes
	namedCurveOID := new(asn1.ObjectIdentifier)
	if _, err := asn1.Unmarshal(paramsDer, namedCurveOID); err != nil {
		namedCurveOID = nil
	}
	if namedCurveOID != nil && !namedCurveOID.Equal(oidNamedCurveS256) {
		return x509.ParsePKCS8PrivateKey(derBytes)
	}

	var privKey ecPrivateKey
	if _, err := asn1.Unmarshal(pkcs8PrivKey.PrivateKey, &privKey); err != nil {
		return nil, fmt.Errorf("x509: failed to parse EC private key: %w", err)
	}
	if privKey.Version != ecPrivKeyVersion {
		return nil, fmt.Errorf("x509: unknown EC private key version %d", privKey.Version)
	}

	if namedCurveOID == nil {
		if privKey.NamedCurveOID == nil {
			return nil, fmt.Errorf("x509: unknown elliptic curve")
		}
		if !privKey.NamedCurveOID.Equal(oidNamedCurveS256) {
			return x509.ParsePKCS8PrivateKey(derBytes)
		}
	}

	k := new(big.Int).SetBytes(privKey.PrivateKey)
	curveOrder := secp256k1.S256().Params().N
	if k.Cmp(curveOrder) >= 0 {
		return nil, errors.New("x509: invalid elliptic curve private key value")
	}
	priv := new(ecdsa.PrivateKey)
	priv.Curve = secp256k1.S256()
	priv.D = k

	privateKey := make([]byte, (curveOrder.BitLen()+7)/8)

	// Some private keys have leading zero padding. This is invalid
	// according to [SEC1], but this code will ignore it.
	for len(privKey.PrivateKey) > len(privateKey) {
		if privKey.PrivateKey[0] != 0 {
			return nil, errors.New("x509: invalid private key length")
		}
		privKey.PrivateKey = privKey.PrivateKey[1:]
	}

	// Some private keys remove all leading zeros, this is also invalid
	// according to [SEC1] but since OpenSSL used to do this, we ignore
	// this too.
	copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)
	priv.X, priv.Y = secp256k1.S256().ScalarBaseMult(privateKey)

	return priv, nil
}
