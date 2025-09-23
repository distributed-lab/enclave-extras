package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/distributed-lab/enclave-extras/attestation/kmshelpers"
	"github.com/distributed-lab/enclave-extras/nsm"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/log"
)

const (
	region    = "you_region"
	accessKey = "iam_access_key"
	secretKey = "iam_secret_key"
)

func main() {
	time.Sleep(15 * time.Second)

	awsConfig, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region), config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")))
	if err != nil {
		panic(fmt.Errorf("failed to load default aws config: %w", err))
	}

	fmt.Println("All pcrs values: should be zeros at start")
	for i := 0; i < 32; i++ {
		_, pcrData, err := nsm.DescribePCR(i)
		if err != nil {
			panic(fmt.Errorf("failed to get pcr0 data: %w", err))
		}
		fmt.Printf("PCR%d data: %s\n", i, hexutil.Encode(pcrData))
	}

	_, pcr0Data, err := nsm.DescribePCR(0)
	if err != nil {
		panic(fmt.Errorf("failed to get pcr0 data: %w", err))
	}

	keyID, err := CreateKMSEnclaveKey(awsConfig, map[string]string{
		"kms:RecipientAttestation:PCR0": hex.EncodeToString(pcr0Data),
	})
	if err != nil {
		panic(fmt.Errorf("failed to create kms key: %w", err))
	}
	fmt.Printf("KeyID: %s\n", keyID)

	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(fmt.Errorf("failed to generate rsa 4096 private key: %w", err))
	}
	fmt.Printf("PrivateKey: %s\n", hexutil.Encode(x509.MarshalPKCS1PrivateKey(rsaPrivateKey)))
	fmt.Printf("PublicKey: %s\n", hexutil.Encode(x509.MarshalPKCS1PublicKey(&rsaPrivateKey.PublicKey)))

	derEncodedPublicKey, err := x509.MarshalPKIXPublicKey(&rsaPrivateKey.PublicKey)
	if err != nil {
		panic(fmt.Errorf("failed to encode public key in DER format: %w", err))
	}
	fmt.Printf("DEREncodedPublicKey: %s\n", hexutil.Encode(derEncodedPublicKey))

	attestationDoc, err := nsm.GetAttestationDoc(nil, nil, derEncodedPublicKey)
	if err != nil {
		panic(fmt.Errorf("failed to get attestatiokn doc: %w", err))
	}
	fmt.Printf("AttestationDoc: %s\n", hexutil.Encode(attestationDoc))

	awsKMSEnclaveClient := kmshelpers.NewFromConfig(awsConfig)

	encryptResp, err := awsKMSEnclaveClient.Encrypt(context.TODO(), &kms.EncryptInput{
		KeyId:     aws.String(keyID),
		Plaintext: []byte("Hello world"),
	})
	if err != nil {
		panic(fmt.Errorf("failed to encrypt plaintext: %w", err))
	}
	fmt.Printf("Ciphertext: %s\n", hexutil.Encode(encryptResp.CiphertextBlob))

	decryptResp, err := awsKMSEnclaveClient.Decrypt(context.TODO(), &kms.DecryptInput{
		KeyId:          aws.String(keyID),
		CiphertextBlob: encryptResp.CiphertextBlob,
		Recipient: &kmstypes.RecipientInfo{
			AttestationDocument:    attestationDoc,
			KeyEncryptionAlgorithm: kmstypes.KeyEncryptionMechanismRsaesOaepSha256,
		},
	}, rsaPrivateKey)
	if err != nil {
		panic(fmt.Errorf("failed to decrypt ciphertext on KMS: %w", err))
	}
	fmt.Printf("Plaintext(decrypt): %s\n", string(decryptResp.Plaintext))

	generateDataKeyResp, err := awsKMSEnclaveClient.GenerateDataKey(context.TODO(), &kms.GenerateDataKeyInput{
		KeyId:   aws.String(keyID),
		KeySpec: kmstypes.DataKeySpecAes256,
		Recipient: &kmstypes.RecipientInfo{
			AttestationDocument:    attestationDoc,
			KeyEncryptionAlgorithm: kmstypes.KeyEncryptionMechanismRsaesOaepSha256,
		},
	}, rsaPrivateKey)
	if err != nil {
		panic(fmt.Errorf("failed to generate data key on KMS: %w", err))
	}
	fmt.Printf("Plaintext(generate-data-key): %s\n", hexutil.Encode(generateDataKeyResp.Plaintext))

	generateDataKeyPairResp, err := awsKMSEnclaveClient.GenerateDataKeyPair(context.TODO(), &kms.GenerateDataKeyPairInput{
		KeyId:       aws.String(keyID),
		KeyPairSpec: kmstypes.DataKeyPairSpecEccNistP521,
		Recipient: &kmstypes.RecipientInfo{
			AttestationDocument:    attestationDoc,
			KeyEncryptionAlgorithm: kmstypes.KeyEncryptionMechanismRsaesOaepSha256,
		},
	}, rsaPrivateKey)
	if err != nil {
		panic(fmt.Errorf("failed to generate data key pair on KMS: %w", err))
	}
	fmt.Printf("PrivateKeyPlaintext(generate-data-key-pair): %s\n", hexutil.Encode(generateDataKeyPairResp.PrivateKeyPlaintext))
	fmt.Printf("PublicKey: %s\n", hexutil.Encode(generateDataKeyPairResp.PublicKey))

	generateRandomResp, err := awsKMSEnclaveClient.GenerateRandom(context.TODO(), &kms.GenerateRandomInput{
		NumberOfBytes: aws.Int32(128),
		Recipient: &kmstypes.RecipientInfo{
			AttestationDocument:    attestationDoc,
			KeyEncryptionAlgorithm: kmstypes.KeyEncryptionMechanismRsaesOaepSha256,
		},
	}, rsaPrivateKey)
	if err != nil {
		panic(fmt.Errorf("failed to genearate random on KMS: %w", err))
	}
	fmt.Printf("Plaintext(generate-random): %s\n", hexutil.Encode(generateRandomResp.Plaintext))
}

func CreateKMSEnclaveKey(cfg aws.Config, pcrs map[string]string) (string, error) {
	callerARN, err := getCallerARN(cfg)
	if err != nil {
		return "", fmt.Errorf("failed to get arn of active user: %w", err)
	}

	log.Debug("Create KMS Restricted key: Caller ARN", callerARN)

	rootARN, err := arn.Parse(callerARN)
	if err != nil {
		return "", fmt.Errorf("failed to parse arn: %w", err)
	}
	rootARN.Resource = "root"

	log.Debug("Create KMS Restricted key: Root ARN", rootARN.String())

	keyPolicy := map[string]interface{}{
		"Version": "2012-10-17",
		"Id":      "key-default-1",
		"Statement": []map[string]interface{}{
			{
				"Sid":    "Allow access for Key Administrators",
				"Effect": "Allow",
				"Principal": map[string]interface{}{
					"AWS": rootARN.String(),
				},
				"Action": []string{
					"kms:CancelKeyDeletion",
					"kms:DescribeKey",
					"kms:DisableKey",
					"kms:EnableKey",
					"kms:GetKeyPolicy",
					"kms:ScheduleKeyDeletion",
				},
				"Resource": "*",
			},
			// should be removed if you want to
			// trust private key generated in enclave
			{
				"Sid":    "Enable encrypt from instance",
				"Effect": "Allow",
				"Principal": map[string]interface{}{
					"AWS": callerARN,
				},
				"Action":   "kms:Encrypt",
				"Resource": "*",
			},
			{
				"Sid":    "Enable decrypt from enclave",
				"Effect": "Allow",
				"Principal": map[string]interface{}{
					"AWS": callerARN,
				},
				"Action": []string{
					"kms:Decrypt",
					"kms:GenerateRandom",
					"kms:GenerateDataKey",
					"kms:GenerateDataKeyPair",
				},
				"Resource": "*",
				"Condition": map[string]interface{}{
					"StringEqualsIgnoreCase": pcrs,
				},
			},
		},
	}

	policyBytes, err := json.Marshal(keyPolicy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal policy: %w", err)
	}

	log.Debug("Create KMS Restricted key: Key policy", string(policyBytes))

	awsKMSClient := kms.NewFromConfig(cfg)
	resp, err := awsKMSClient.CreateKey(context.TODO(), &kms.CreateKeyInput{
		// DANGER: The key may become unmanageable
		BypassPolicyLockoutSafetyCheck: true,
		Description:                    aws.String("Nitro Enclave Key"),
		Policy:                         aws.String(string(policyBytes)),
	})
	if err != nil {
		return "", fmt.Errorf("failed to create kms key")
	}

	// Should never be nil
	return *resp.KeyMetadata.KeyId, nil
}

func getCallerARN(cfg aws.Config) (string, error) {
	awsIAMClient := iam.NewFromConfig(cfg)
	resp, err := awsIAMClient.GetUser(context.TODO(), &iam.GetUserInput{})
	if err != nil {
		return "", err
	}

	// Should never be nil
	return *resp.User.Arn, nil
}
