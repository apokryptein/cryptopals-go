package cmd

import (
	"fmt"
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
	RunE: func(cmd *cobra.Command, args []string) error {
		// Parse int for set
		set, err := parseInt(args[0], "set")
		if err != nil {
			return err
		}

		// Parse int for challenge
		challenge, err := parseInt(args[1], "challenge")
		if err != nil {
			return err
		}

		// Call challenge's runner function
		if err := runner.Run(set, challenge); err != nil {
			return fmt.Errorf("failed to run challenge: %w", err)
		}

		return nil
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
