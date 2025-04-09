package kms

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/distributed-lab/enclave-extras/attestation/kmshelpers"
	"github.com/distributed-lab/enclave-extras/nsm"
)

type GenerateDataKeyOptions struct {
	Profile       string
	KeyID         string
	NumberOfBytes int32
}

func GenerateDataKey(opts GenerateDataKeyOptions) error {
	awsConfig, err := config.LoadDefaultConfig(context.TODO(), config.WithSharedConfigProfile(opts.Profile))
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}
	kmsEnclaveClient := kmshelpers.NewFromConfig(awsConfig)

	sessionPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("failed to generate RSA private key: %w", err)
	}
	derEncodedSessionPublicKey, err := x509.MarshalPKIXPublicKey(&sessionPrivateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("faield to marshal public key PKIX: %w", err)
	}
	kmsAttestationDocRaw, err := nsm.GetAttestationDoc(nil, nil, derEncodedSessionPublicKey)
	if err != nil {
		return fmt.Errorf("failed to get attestation doc with public key: %w", err)
	}

	generateDataKeyResp, err := kmsEnclaveClient.GenerateDataKey(context.TODO(), &kms.GenerateDataKeyInput{
		KeyId:         aws.String(opts.KeyID),
		NumberOfBytes: aws.Int32(opts.NumberOfBytes),
		Recipient: &kmstypes.RecipientInfo{
			AttestationDocument:    kmsAttestationDocRaw,
			KeyEncryptionAlgorithm: kmstypes.KeyEncryptionMechanismRsaesOaepSha256,
		},
	}, sessionPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to generate data key: %w", err)
	}

	fmt.Printf("%s", generateDataKeyResp.CiphertextBlob)
	return nil
}
