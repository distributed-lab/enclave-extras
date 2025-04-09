package kms

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/distributed-lab/enclave-extras/nsm"
)

type CreateKeyOptions struct {
	Profile     string
	ManagedKey  bool
	IncludePCRs map[int]struct{}
}

func CreateKey(opts CreateKeyOptions) error {
	awsConfig, err := config.LoadDefaultConfig(context.TODO(), config.WithSharedConfigProfile(opts.Profile))
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}
	stsClient := sts.NewFromConfig(awsConfig)
	kmsClient := kms.NewFromConfig(awsConfig)

	pcrConditions := make(map[string]string)
	for pcr := range opts.IncludePCRs {
		_, pcrData, err := nsm.DescribePCR(pcr)
		if err != nil {
			return err
		}
		pcrConditions[nsm.PCRxCondition(pcr)] = hex.EncodeToString(pcrData)
	}

	getCallerIdentityOutput, err := stsClient.GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("failed to get caller identity: %w", err)
	}

	rootARN, err := arn.Parse(safeStringDeref(getCallerIdentityOutput.Arn))
	if err != nil {
		return fmt.Errorf("failed to parse caller ARN: %w", err)
	}
	rootARN.Resource = "root"

	kmsKeyPolicy := defaultEnclaveKMSKeyPolicies(rootARN.String(), safeStringDeref(getCallerIdentityOutput.Arn), pcrConditions, opts.ManagedKey)

	createKeyOutput, err := kmsClient.CreateKey(context.TODO(), &kms.CreateKeyInput{
		// DANGER: The key may become unmanageable
		BypassPolicyLockoutSafetyCheck: true,
		Description:                    aws.String("Nitro Enclave Key"),
		Policy:                         aws.String(kmsKeyPolicy),
	})
	if err != nil {
		return fmt.Errorf("failed to create KMS key: %w", err)
	}
	kmsKeyID := safeStringDeref(createKeyOutput.KeyMetadata.KeyId)
	fmt.Printf("%s", kmsKeyID)
	return nil
}

func defaultEnclaveKMSKeyPolicies(rootARN, principalARN string, pcrs map[string]string, managedKey bool) string {
	rootActions := []string{
		"kms:CancelKeyDeletion",
		"kms:DescribeKey",
		"kms:DisableKey",
		"kms:EnableKey",
		"kms:GetKeyPolicy",
		"kms:ScheduleKeyDeletion",
	}

	if managedKey {
		rootActions = append(rootActions, "kms:PutKeyPolicy")
	}

	defaultPolicy := map[string]interface{}{
		"Version": "2012-10-17",
		"Id":      "key-default-1",
		"Statement": []map[string]interface{}{
			{
				"Sid":    "Allow access for Key Administrators",
				"Effect": "Allow",
				"Principal": map[string]interface{}{
					"AWS": rootARN,
				},
				"Action":   rootActions,
				"Resource": "*",
			},
			{
				"Sid":    "Enable enclave",
				"Effect": "Allow",
				"Principal": map[string]interface{}{
					"AWS": principalARN,
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

	// should never panic
	policy, _ := json.Marshal(defaultPolicy)
	return string(policy)
}

func safeStringDeref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
