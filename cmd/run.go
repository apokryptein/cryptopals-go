package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run a specific Cryptopals challenge",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		// TODO: do this
		fmt.Println("run called")
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
}
