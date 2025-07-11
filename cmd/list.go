package cmd

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/apokryptein/cryptopals-go/internal/runner"
	"github.com/spf13/cobra"
)

// listCmd represents the list command
var (
	showAll bool

	listCmd = &cobra.Command{
		Use:   "list",
		Short: "List all challenges",
		Long:  `List all challenges grouped by set.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return listAllChallenges()
		},
	}
)

func init() {
	rootCmd.AddCommand(listCmd)
	listCmd.Flags().BoolVarP(&showAll, "all", "a", false, "show all details including descriptions")
}

func listAllChallenges() error {
	challenges := runner.GetAll()
	if len(challenges) == 0 {
		fmt.Println("No challenges registered")
		return nil
	}

	// Group by set
	sets := make(map[int][]*runner.Challenge)
	for _, c := range challenges {
		sets[c.Set] = append(sets[c.Set], c)
	}

	// Get sorted set numbers
	var setNumbers []int
	for set := range sets {
		setNumbers = append(setNumbers, set)
	}
	sort.Ints(setNumbers)

	// Instantiate new table writer
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()

	// Header
	fmt.Fprintln(w, "Cryptopals Challenges")
	fmt.Fprintln(w, "====================")

	// Iterate over sorted set numbers
	for _, set := range setNumbers {
		challenges := sets[set]

		// Sort challenges within each set by number
		sort.Slice(challenges, func(i, j int) bool {
			return challenges[i].Number < challenges[j].Number
		})

		// Show current set
		fmt.Fprintf(w, "\nSet %d:\n", set)

		// Check for showAll and build/print appropriate header
		if showAll {
			fmt.Fprintln(w, "ID\tName\tStatus\tDescription")
			fmt.Fprintln(w, "──\t────\t──────\t───────────")
		} else {
			fmt.Fprintln(w, "ID\tName\tStatus")
			fmt.Fprintln(w, "──\t────\t──────")
		}

		// Iterate over challenges in current set
		for _, c := range challenges {
			// Check impelementation status
			status := "✓"
			if !c.Implemented {
				status = "○"
			}

			// Check for presence of description
			if showAll && c.Description != "" {
				fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", c.Number, c.Name, status, c.Description)
			} else {
				fmt.Fprintf(w, "%d\t%s\t%s\n", c.Number, c.Name, status)
			}
		}
	}

	// Print key for reference
	fmt.Fprintln(w, "\n✓ = implemented, ○ = not implemented")

	return nil
}
