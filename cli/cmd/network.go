package cmd

import (
	"fmt"
	"sort"

	"github.com/AlecAivazis/survey/v2"
	"github.com/spf13/cobra"

	"github.com/oasisprotocol/oasis-sdk/cli/cmd/common"
	"github.com/oasisprotocol/oasis-sdk/cli/config"
	"github.com/oasisprotocol/oasis-sdk/cli/table"
)

var (
	networkCmd = &cobra.Command{
		Use:   "network",
		Short: "Manage network endpoints",
	}

	networkListCmd = &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List configured networks",
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.Global()
			table := table.New()
			table.SetHeader([]string{"Name", "Chain Context", "RPC"})

			var output [][]string
			for name, net := range cfg.Networks.All {
				output = append(output, []string{
					name,
					net.ChainContext,
					net.RPC,
				})
			}

			// Sort output by name.
			sort.Slice(output, func(i, j int) bool {
				return output[i][0] < output[j][0]
			})

			table.AppendBulk(output)
			table.Render()
		},
	}

	networkAddCmd = &cobra.Command{
		Use:   "add <name> <chain-context> <rpc-endpoint>",
		Short: "Add a new network",
		Args:  cobra.ExactArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.Global()
			name, chainContext, rpc := args[0], args[1], args[2]

			// Ask user for some additional parameters.
			questions := []*survey.Question{
				{
					Name:   "description",
					Prompt: &survey.Input{Message: "Description:"},
				},
				{
					Name:   "symbol",
					Prompt: &survey.Input{Message: "Denomination symbol:"},
				},
				{
					Name: "decimals",
					Prompt: &survey.Input{
						Message: "Denomination decimal places:",
						Default: "9",
					},
					Validate: survey.Required,
				},
			}
			answers := struct {
				Description string
				Symbol      string
				Decimals    uint8
			}{}
			err := survey.Ask(questions, &answers)
			cobra.CheckErr(err)

			err = cfg.Networks.Add(name, &config.Network{
				Description:  answers.Description,
				ChainContext: chainContext,
				RPC:          rpc,
				Denomination: config.DenominationInfo{
					Symbol:   answers.Symbol,
					Decimals: answers.Decimals,
				},
			})
			cobra.CheckErr(err)

			err = cfg.Save()
			cobra.CheckErr(err)
		},
	}

	networkRmCmd = &cobra.Command{
		Use:     "rm <name>",
		Aliases: []string{"remove"},
		Short:   "Remove an existing network",
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.Global()
			name := args[0]

			net, exists := cfg.Networks.All[name]
			if !exists {
				cobra.CheckErr(fmt.Errorf("network '%s' does not exist", name))
			}

			if len(net.ParaTimes.All) > 0 {
				fmt.Printf("WARNING: Network '%s' contains %d paratimes.\n", name, len(net.ParaTimes.All))
				common.Confirm("Are you sure you want to remove the network?", "not removing network")
			}

			err := cfg.Networks.Remove(name)
			cobra.CheckErr(err)

			err = cfg.Save()
			cobra.CheckErr(err)
		},
	}

	networkSetDefaultCmd = &cobra.Command{
		Use:   "set-default <name>",
		Short: "Sets the given network as the default network",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.Global()
			name := args[0]

			err := cfg.Networks.SetDefault(name)
			cobra.CheckErr(err)

			err = cfg.Save()
			cobra.CheckErr(err)
		},
	}

	networkSetRPCCmd = &cobra.Command{
		Use:   "set-rpc <name> <rpc-endpoint>",
		Short: "Sets the RPC endpoint of the given network",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.Global()
			name, rpc := args[0], args[1]

			net := cfg.Networks.All[name]
			if net == nil {
				cobra.CheckErr(fmt.Errorf("network '%s' does not exist", name))
			}

			net.RPC = rpc

			err := cfg.Save()
			cobra.CheckErr(err)
		},
	}
)

func init() {
	networkCmd.AddCommand(networkListCmd)
	networkCmd.AddCommand(networkAddCmd)
	networkCmd.AddCommand(networkRmCmd)
	networkCmd.AddCommand(networkSetDefaultCmd)
	networkCmd.AddCommand(networkSetRPCCmd)
}
