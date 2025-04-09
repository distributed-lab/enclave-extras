package kms

import (
	"fmt"

	"github.com/spf13/cobra"
)

var generateDataKeyPairCmd = &cobra.Command{
	Use:   "generate-data-key-pair",
	Short: "Not implemented!",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Not implemented!")
		return nil
	},
}
