package kmshelpers

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type KMSEnclaveClient struct {
	kms.Client
}

func NewFromConfig(cfg aws.Config, optFns ...func(*kms.Options)) *KMSEnclaveClient {
	return &KMSEnclaveClient{*kms.NewFromConfig(cfg, optFns...)}
}

func (k *KMSEnclaveClient) Decrypt(ctx context.Context, params *kms.DecryptInput, pk *rsa.PrivateKey, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if params == nil || params.Recipient == nil {
		return nil, fmt.Errorf("kms enclave client: recipient required")
	}
	if pk == nil {
		return nil, fmt.Errorf("kms enclave client: rsa private key required")
	}

	decryptOutput, err := k.Client.Decrypt(ctx, params, optFns...)
	if err != nil {
		return nil, err
	}

	plaintext, err := DecryptCiphertextForRicipient(decryptOutput.CiphertextForRecipient, pk)
	if err != nil {
		return nil, err
	}

	decryptOutput.Plaintext = plaintext
	return decryptOutput, nil
}

func (k *KMSEnclaveClient) GenerateDataKey(ctx context.Context, params *kms.GenerateDataKeyInput, pk *rsa.PrivateKey, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	if params == nil || params.Recipient == nil {
		return nil, fmt.Errorf("kms enclave client: recipient required")
	}
	if pk == nil {
		return nil, fmt.Errorf("kms enclave client: rsa private key required")
	}

	generateDataKeyOutput, err := k.Client.GenerateDataKey(ctx, params, optFns...)
	if err != nil {
		return nil, err
	}

	plaintext, err := DecryptCiphertextForRicipient(generateDataKeyOutput.CiphertextForRecipient, pk)
	if err != nil {
		return nil, err
	}

	generateDataKeyOutput.Plaintext = plaintext
	return generateDataKeyOutput, nil
}

func (k *KMSEnclaveClient) GenerateDataKeyPair(ctx context.Context, params *kms.GenerateDataKeyPairInput, pk *rsa.PrivateKey, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyPairOutput, error) {
	if params == nil || params.Recipient == nil {
		return nil, fmt.Errorf("kms enclave client: recipient required")
	}
	if pk == nil {
		return nil, fmt.Errorf("kms enclave client: rsa private key required")
	}

	generateDataKeyPairOutput, err := k.Client.GenerateDataKeyPair(ctx, params, optFns...)
	if err != nil {
		return nil, err
	}

	privateKeyPlaintext, err := DecryptCiphertextForRicipient(generateDataKeyPairOutput.CiphertextForRecipient, pk)
	if err != nil {
		return nil, err
	}

	generateDataKeyPairOutput.PrivateKeyPlaintext = privateKeyPlaintext
	return generateDataKeyPairOutput, nil
}

func (k *KMSEnclaveClient) GenerateRandom(ctx context.Context, params *kms.GenerateRandomInput, pk *rsa.PrivateKey, optFns ...func(*kms.Options)) (*kms.GenerateRandomOutput, error) {
	if params == nil || params.Recipient == nil {
		return nil, fmt.Errorf("kms enclave client: recipient required")
	}
	if pk == nil {
		return nil, fmt.Errorf("kms enclave client: rsa private key required")
	}

	generateRandomOutput, err := k.Client.GenerateRandom(ctx, params, optFns...)
	if err != nil {
		return nil, err
	}

	plaintext, err := DecryptCiphertextForRicipient(generateRandomOutput.CiphertextForRecipient, pk)
	if err != nil {
		return nil, err
	}

	generateRandomOutput.Plaintext = plaintext
	return generateRandomOutput, nil
}

func DecryptCiphertextForRicipient(raw []byte, privateKey *rsa.PrivateKey) (plaintext []byte, err error) {
	pkcs7Data, err := ParsePKCS7(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ciphertext for ricipient: %w", err)
	}

	if len(pkcs7Data.Content.RecipientInfos) == 0 {
		return nil, fmt.Errorf("invalid recipient info")
	}

	encryptedAESKey := pkcs7Data.Content.RecipientInfos[0].EncryptedKey
	iv := pkcs7Data.Content.EncryptedContentInfo.ContentEncryptionAlgorithm.Parameters.Bytes
	ciphertext := pkcs7Data.Content.EncryptedContentInfo.EncryptedContent

	aesKey, err := rsa.DecryptOAEP(sha256.New(), nil, privateKey, encryptedAESKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt aes key: %w", err)
	}

	aesCipher, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create aes cipher: %w", err)
	}

	cbcAESCipher := cipher.NewCBCDecrypter(aesCipher, iv)

	plaintext = make([]byte, len(ciphertext))
	cbcAESCipher.CryptBlocks(plaintext, ciphertext)

	plaintext, err = pkcs7Strip(plaintext, aes.BlockSize)
	if err != nil {
		panic(err)
	}

	return plaintext, nil
}
