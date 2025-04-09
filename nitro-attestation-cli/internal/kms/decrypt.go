package kms

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/distributed-lab/enclave-extras/attestation/kmshelpers"
	"github.com/distributed-lab/enclave-extras/nsm"
)

type DecryptOptions struct {
	Profile string
	KeyID   string
	Input   string
}

func Decrypt(opts DecryptOptions) error {
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

	encryptedData, err := os.ReadFile(opts.Input)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	decryptResp, err := kmsEnclaveClient.Decrypt(context.TODO(), &kms.DecryptInput{
		KeyId:          aws.String(opts.KeyID),
		CiphertextBlob: encryptedData,
		Recipient: &kmstypes.RecipientInfo{
			AttestationDocument:    kmsAttestationDocRaw,
			KeyEncryptionAlgorithm: kmstypes.KeyEncryptionMechanismRsaesOaepSha256,
		},
	}, sessionPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %w", err)
	}

	fmt.Printf("%s", decryptResp.Plaintext)
	return nil
}
