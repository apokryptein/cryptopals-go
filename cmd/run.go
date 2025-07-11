package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/apokryptein/cryptopals-go/internal/runner"
	"github.com/spf13/cobra"
)

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run [set] [challenge]",
	Short: "Run a specific Cryptopals challenge",
	Long:  ``,
	Args:  cobra.ExactArgs(2),
	Example: `  cryptopals run 1 3
  cryptopals run 2 10`,
	Run: func(cmd *cobra.Command, args []string) {
		// Parse int for set
		set, err := parseInt(args[0], "set")
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Challenge failure: %v\n", err)
			os.Exit(1)
		}

		// Parse int for challenge
		challenge, err := parseInt(args[1], "challenge")
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to parse arguments: %v\n", err)
			os.Exit(1)
		}

		// Call challenge's runner function
		if err := runner.Run(set, challenge); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Challenge failure: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
}

// parseInt is a helper function to consolidate string to int conversion
func parseInt(s string, name string) (int, error) {
	// Parse string to int
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid %s number: %s", name, s)
	}

	// Ensure the number makes sense
	if n < 1 || n > 66 {
		return 0, fmt.Errorf("%s must be between 1-66", name)
	}
	return n, nil
}
