package kms

import (
	"fmt"

	"github.com/distributed-lab/enclave-extras/nitro-attestation-cli/internal/kms"
	"github.com/spf13/cobra"
)

var (
	createKeyProfile      string
	createKeyManagedKey   bool
	createKeyIncludedPCRs = map[int]struct{}{}
)

var createKeyCmd = &cobra.Command{
	Use:   "create-key",
	Short: "",
	Long:  "",
	RunE: func(cmd *cobra.Command, args []string) error {
		if createKeyProfile == "" {
			createKeyProfile = "default"
		}
		return kms.CreateKey(kms.CreateKeyOptions{
			Profile:     createKeyProfile,
			ManagedKey:  createKeyManagedKey,
			IncludePCRs: createKeyIncludedPCRs,
		})
	},
}

func init() {
	createKeyCmd.Flags().StringVar(&createKeyProfile, "profile", "", "AWS Config profile")
	createKeyCmd.Flags().BoolVar(&createKeyManagedKey, "managed-key", false, "Allow to root change key policies")

	addIncludedPCRFlags(createKeyCmd)
}

func addIncludedPCRFlags(cmd *cobra.Command) {
	for pcr := 0; pcr < 32; pcr++ {
		cmd.Flags().Bool(fmt.Sprintf("pcr%d", pcr), false, fmt.Sprintf("Include PCR %d", pcr))
	}
	cmd.PreRun = func(cmd *cobra.Command, args []string) {
		for pcr := 0; pcr < 32; pcr++ {
			val, err := cmd.Flags().GetBool(fmt.Sprintf("pcr%d", pcr))
			if err == nil && val {
				createKeyIncludedPCRs[pcr] = struct{}{}
			}
		}
	}
}
