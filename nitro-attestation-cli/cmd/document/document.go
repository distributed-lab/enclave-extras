package document

import (
	"github.com/spf13/cobra"
)

var Cmd = &cobra.Command{
	Use:   "document",
	Short: "Create and read AWS Nitro Secure Module attestation documents",
}

func init() {
	Cmd.AddCommand(createCmd)
	Cmd.AddCommand(readCmd)
}
