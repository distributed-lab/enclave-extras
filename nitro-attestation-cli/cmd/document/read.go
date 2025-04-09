package document

import (
	"fmt"

	"github.com/distributed-lab/enclave-extras/nitro-attestation-cli/internal/document"
	"github.com/spf13/cobra"
)

var (
	readInput     string
	readPublicKey bool
	readUserData  bool
	readNonce     bool
	pcrsToVerify  = map[int]struct{}{}
)

var readCmd = &cobra.Command{
	Use:   "read",
	Short: "",
	Long:  "",
	RunE: func(cmd *cobra.Command, args []string) error {
		return document.ReadAttestationDocument(document.ReadAttestationDocumentOptions{
			UserData:     readUserData,
			Nonce:        readNonce,
			PublicKey:    readPublicKey,
			Input:        readInput,
			PCRsToVerify: pcrsToVerify,
		})
	},
}

func init() {
	readCmd.Flags().StringVar(&readInput, "input", "", "Input file to read")
	readCmd.Flags().BoolVar(&readPublicKey, "public-key", false, "Print public key as raw string")
	readCmd.Flags().BoolVar(&readUserData, "user-data", false, "Print user data as raw string")
	readCmd.Flags().BoolVar(&readNonce, "nonce", false, "Print nonce as raw string")

	readCmd.MarkFlagRequired("input")
	addVerifyPCRFlags(readCmd)
}

func addVerifyPCRFlags(cmd *cobra.Command) {
	for pcr := 0; pcr < 32; pcr++ {
		cmd.Flags().Bool(fmt.Sprintf("verify-pcr%d", pcr), false, fmt.Sprintf("Verify PCR %d", pcr))
	}
	cmd.PreRun = func(cmd *cobra.Command, args []string) {
		for pcr := 0; pcr < 32; pcr++ {
			val, err := cmd.Flags().GetBool(fmt.Sprintf("verify-pcr%d", pcr))
			if err == nil && val {
				pcrsToVerify[pcr] = struct{}{}
			}
		}
	}
}
