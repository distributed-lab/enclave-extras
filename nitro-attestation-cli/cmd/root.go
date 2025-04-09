package cmd

import (
	"fmt"

	"github.com/distributed-lab/enclave-extras/nitro-attestation-cli/cmd/document"
	"github.com/distributed-lab/enclave-extras/nitro-attestation-cli/cmd/kms"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "nitro-attestation-cli",
	Short: "CLI for interract with NSM module and AWS KMS",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Welcome to nitro-attestation-cli! Use --help for usage.")
	},
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	rootCmd.AddCommand(document.Cmd)
	rootCmd.AddCommand(kms.Cmd)
}
