package document

import (
	"encoding/hex"
	"fmt"

	"github.com/distributed-lab/enclave-extras/nitro-attestation-cli/internal/document"
	"github.com/spf13/cobra"
)

var (
	createPublicKey string
	createUserData  string
	createNonce     string
)

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "",
	Long:  "",
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		var publicKey []byte
		if len(createPublicKey) != 0 {
			publicKey, err = hex.DecodeString(createPublicKey)
			if err != nil {
				return fmt.Errorf("invalid public key: %w", err)
			}
		}
		var userData []byte
		if len(createUserData) != 0 {
			userData, err = hex.DecodeString(createUserData)
			if err != nil {
				return fmt.Errorf("invalid user data: %w", err)
			}
		}
		var nonce []byte
		if len(createNonce) != 0 {
			nonce, err = hex.DecodeString(createNonce)
			if err != nil {
				return fmt.Errorf("invalid nonce: %w", err)
			}
		}
		return document.CreateAttestationDocument(document.CreateAttestationDocumentOptions{
			UserData:  userData,
			Nonce:     nonce,
			PublicKey: publicKey,
		})
	},
}

func init() {
	createCmd.Flags().StringVar(&createPublicKey, "public-key", "", "Hex public key")
	createCmd.Flags().StringVar(&createUserData, "user-data", "", "Hex user data")
	createCmd.Flags().StringVar(&createNonce, "nonce", "", "Hex nonce")
}
