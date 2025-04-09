package kms

import (
	"fmt"

	"github.com/distributed-lab/enclave-extras/nitro-attestation-cli/internal/kms"
	"github.com/spf13/cobra"
)

var (
	generateDataKeyProfile       string
	generateDataKeyKeyID         string
	generateDataKeyNumberOfBytes int32
)

var generateDataKeyCmd = &cobra.Command{
	Use:   "generate-data-key",
	Short: "",
	Long:  "",
	RunE: func(cmd *cobra.Command, args []string) error {
		if generateDataKeyProfile == "" {
			generateDataKeyProfile = "default"
		}
		// Nitro attestation use RSAES_OAEP_SHA_256 with max size 446 bit encrypted content
		// https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html
		// 446 / 8 = 55
		if generateDataKeyNumberOfBytes < 1 || generateDataKeyNumberOfBytes > 55 {
			return fmt.Errorf("invalid number of bytes, must be between 1 and 55")
		}
		return kms.GenerateDataKey(kms.GenerateDataKeyOptions{
			Profile:       generateDataKeyProfile,
			KeyID:         generateDataKeyKeyID,
			NumberOfBytes: generateDataKeyNumberOfBytes,
		})
	},
}

func init() {
	generateDataKeyCmd.Flags().StringVar(&generateDataKeyProfile, "profile", "", "AWS Config profile")
	generateDataKeyCmd.Flags().StringVar(&generateDataKeyKeyID, "key-id", "", "AWS KMS key ID")
	generateDataKeyCmd.Flags().Int32Var(&generateDataKeyNumberOfBytes, "number-of-bytes", 32, "Key length")

	generateDataKeyCmd.MarkFlagRequired("key-id")
}
