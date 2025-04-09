package kms

import (
	"github.com/spf13/cobra"
)

var Cmd = &cobra.Command{
	Use:   "kms",
	Short: "Interact with AWS KMS from enclave with attestation document",
}

func init() {
	Cmd.AddCommand(createKeyCmd)
	Cmd.AddCommand(decryptCmd)
	Cmd.AddCommand(generateDataKeyCmd)
	Cmd.AddCommand(generateDataKeyPairCmd)
	Cmd.AddCommand(generateRandomCmd)
}
