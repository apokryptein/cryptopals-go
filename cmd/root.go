// Package cmd handles all CLI command for running Cryptopals challenges
// using Cobra
package cmd

import (
	"github.com/spf13/cobra"

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

	// Disable help subcommand
	rootCmd.SetHelpCommand(&cobra.Command{
		Use:    "no-help",
		Hidden: true,
	})

	// Disable comletion subcommand
	rootCmd.CompletionOptions.DisableDefaultCmd = true
}
