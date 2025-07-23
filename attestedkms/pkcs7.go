package attestedkms

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

type PKCS7 struct {
	ContentType asn1.ObjectIdentifier
	Content     EnvelopedData `asn1:"explicit,tag:0"`
}

type EnvelopedData struct {
	Version              int
	RecipientInfos       []KeyTransRecipientInfo `asn1:"set"`
	EncryptedContentInfo EncryptedContentInfo
}

type KeyTransRecipientInfo struct {
	Version                int
	RID                    []byte `asn1:"tag:0"`
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

type EncryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           [][]byte `asn1:"set,tag:0"`
}

func ParsePKCS7(raw []byte) (*PKCS7, error) {
	raw, err := EnsureDER(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure that raw data in der format: %w", err)
	}

	var info PKCS7
	_, err = asn1.Unmarshal(raw, &info)
	if err != nil {
		panic(fmt.Errorf("failed to unmarshal ASN.1 to PKCS7: %w", err))
	}

	return &info, nil
}

func pkcs7Strip(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("pkcs7: data is empty")
	}
	if length%blockSize != 0 {
		return nil, fmt.Errorf("pkcs7: data is not block-aligned")
	}
	paddingLen := int(data[length-1])
	if paddingLen == 0 || paddingLen > blockSize {
		return nil, fmt.Errorf("pkcs7: invalid pad")
	}
	for i := 0; i < paddingLen; i++ {
		if data[length-1-i] != byte(paddingLen) {
			return nil, fmt.Errorf("pkcs7: invalid pad")
		}
	}
	return data[:length-paddingLen], nil
}
