package kms

import (
	"github.com/distributed-lab/enclave-extras/nitro-attestation-cli/internal/kms"
	"github.com/spf13/cobra"
)

var (
	decryptProfile string
	decryptKeyID   string
	decryptInput   string
)

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "",
	Long:  "",
	RunE: func(cmd *cobra.Command, args []string) error {
		if decryptProfile == "" {
			decryptProfile = "default"
		}
		return kms.Decrypt(kms.DecryptOptions{
			Profile: decryptProfile,
			Input:   decryptInput,
			KeyID:   decryptKeyID,
		})
	},
}

func init() {
	decryptCmd.Flags().StringVar(&decryptProfile, "profile", "", "AWS Config profile")
	decryptCmd.Flags().StringVar(&decryptKeyID, "key-id", "", "AWS KMS key ID")
	decryptCmd.Flags().StringVar(&decryptInput, "input", "", "Input file to decrypt")

	decryptCmd.MarkFlagRequired("input")
	decryptCmd.MarkFlagRequired("key-id")
}
