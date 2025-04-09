package kms

import (
	"fmt"

	"github.com/spf13/cobra"
)

var generateRandomCmd = &cobra.Command{
	Use:   "generate-random",
	Short: "Not implemented!",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Not implemented!")
		return nil
	},
}
