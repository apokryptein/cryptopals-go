// Package cmd handles all CLI command for running Cryptopals challenges
// using Cobra
package cmd

import (
	"github.com/spf13/cobra"

	// TODO: set up challengre registry in challenge init to allow for registration here
	// Setting this here to allow for challenge import
	_ "github.com/apokryptein/cryptopals-go/internal/set1"
	_ "github.com/apokryptein/cryptopals-go/internal/set2"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "cryptopals",
	Short: "Cryptopals challenge runner",
	Long:  `A CLI tool to run Cryptopals crypot challenges`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
