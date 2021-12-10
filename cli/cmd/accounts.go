package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"

	"github.com/oasisprotocol/oasis-sdk/cli/client"
	"github.com/oasisprotocol/oasis-sdk/cli/cmd/common"
	"github.com/oasisprotocol/oasis-sdk/cli/config"
	sdkClient "github.com/oasisprotocol/oasis-sdk/client-sdk/go/client"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/modules/accounts"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/modules/consensusaccounts"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/types"
)

var (
	accountsCmd = &cobra.Command{
		Use:   "accounts",
		Short: "Account operations",
	}

	accountsShowCmd = &cobra.Command{
		Use:   "show [address]",
		Short: "Show account information",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.Global()
			npw := common.GetNPWSelection(cfg)

			// Determine which address to show. If an explicit argument was given, use that
			// otherwise use the selected wallet.
			var targetAddress string
			switch {
			case len(args) >= 1:
				// Explicit argument given.
				targetAddress = args[0]
			case npw.Wallet != nil:
				// Wallet is selected.
				targetAddress = npw.Wallet.Address
			default:
				// No address given and no wallets configured.
				cobra.CheckErr("no address given and no wallets configured")
			}

			// Establish connection with the target network.
			ctx := context.Background()
			c, err := client.Connect(ctx, npw.Network)
			cobra.CheckErr(err)

			addr, err := config.ResolveAddress(npw.Network, targetAddress)
			cobra.CheckErr(err)

			// Query consensus layer account.
			// TODO: Nicer overall formatting.
			fmt.Printf("Address: %s\n", addr)
			fmt.Println()
			fmt.Printf("=== CONSENSUS LAYER (%s) ===\n", npw.NetworkName)

			consensusAccount, err := c.Consensus().Staking().Account(ctx, &staking.OwnerQuery{
				Height: consensus.HeightLatest,
				Owner:  addr.ConsensusAddress(),
			})
			cobra.CheckErr(err)

			fmt.Printf("Balance: %s\n", common.FormatConsensusDenomination(npw.Network, consensusAccount.General.Balance))
			// TODO: Delegations.
			// TODO: Allowances.

			if npw.ParaTime != nil {
				// Query runtime account when a paratime has been configured.
				fmt.Println()
				fmt.Printf("=== %s PARATIME ===\n", npw.ParaTimeName)

				rtBalances, err := c.Runtime(npw.ParaTime).Accounts.Balances(ctx, client.RoundLatest, *addr)
				cobra.CheckErr(err)

				fmt.Printf("Balances for all denominations:\n")
				for denom, balance := range rtBalances.Balances {
					fmt.Printf("  %s\n", common.FormatParaTimeDenomination(npw.ParaTime, types.NewBaseUnits(balance, denom)))
				}
			}
		},
	}

	accountsAllowCmd = &cobra.Command{
		Use:   "allow <beneficiary> <amount>",
		Short: "Configure beneficiary allowance for an account",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.Global()
			npw := common.GetNPWSelection(cfg)
			txCfg := common.GetTransactionConfig()
			beneficiary, amount := args[0], args[1]

			if npw.Wallet == nil {
				cobra.CheckErr("no wallets configured")
			}

			// When not in offline mode, connect to the given network endpoint.
			ctx := context.Background()
			var conn client.Connection
			if !txCfg.Offline {
				var err error
				conn, err = client.Connect(ctx, npw.Network)
				cobra.CheckErr(err)
			}

			// Resolve beneficiary address.
			benAddr, err := config.ResolveAddress(npw.Network, beneficiary)
			cobra.CheckErr(err)

			// Parse amount.
			var negative bool
			if amount[0] == '-' {
				negative = true
				amount = amount[1:]
			}
			amountChange, err := common.ParseConsensusDenomination(npw.Network, amount)
			cobra.CheckErr(err)

			// Prepare transaction.
			tx := staking.NewAllowTx(0, nil, &staking.Allow{
				Beneficiary:  benAddr.ConsensusAddress(),
				Negative:     negative,
				AmountChange: *amountChange,
			})

			wallet := common.LoadWallet(cfg, npw.WalletName)
			sigTx, err := common.SignConsensusTransaction(ctx, npw, wallet, conn, tx)
			cobra.CheckErr(err)

			common.BroadcastTransaction(ctx, npw.ParaTime, conn, sigTx, nil)
		},
	}

	accountsDepositCmd = &cobra.Command{
		Use:   "deposit <amount> [to]",
		Short: "Deposit given amount of tokens into an account in the ParaTime",
		Args:  cobra.RangeArgs(1, 2),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.Global()
			npw := common.GetNPWSelection(cfg)
			txCfg := common.GetTransactionConfig()
			amount := args[0]
			var to string
			if len(args) >= 2 {
				to = args[1]
			}

			if npw.Wallet == nil {
				cobra.CheckErr("no wallets configured")
			}
			if npw.ParaTime == nil {
				cobra.CheckErr("no paratimes to deposit into")
			}

			// When not in offline mode, connect to the given network endpoint.
			ctx := context.Background()
			var conn client.Connection
			if !txCfg.Offline {
				var err error
				conn, err = client.Connect(ctx, npw.Network)
				cobra.CheckErr(err)
			}

			// Resolve destination address when specified.
			var toAddr *types.Address
			if to != "" {
				var err error
				toAddr, err = config.ResolveAddress(npw.Network, to)
				cobra.CheckErr(err)
			}

			// Parse amount.
			// TODO: This should actually query the ParaTime (or config) to check what the consensus
			//       layer denomination is in the ParaTime. Assume NATIVE for now.
			amountBaseUnits, err := common.ParseParaTimeDenomination(npw.ParaTime, amount, types.NativeDenomination)
			cobra.CheckErr(err)

			// Prepare transaction.
			tx := consensusaccounts.NewDepositTx(nil, &consensusaccounts.Deposit{
				To:     toAddr,
				Amount: *amountBaseUnits,
			})

			wallet := common.LoadWallet(cfg, npw.WalletName)
			sigTx, err := common.SignParaTimeTransaction(ctx, npw, wallet, conn, tx)
			cobra.CheckErr(err)

			if txCfg.Offline {
				common.PrintSignedTransaction(sigTx)
				return
			}

			decoder := conn.Runtime(npw.ParaTime).ConsensusAccounts
			waitCh := common.WaitForEvent(ctx, npw.ParaTime, conn, decoder, func(ev sdkClient.DecodedEvent) interface{} {
				ce, ok := ev.(*consensusaccounts.Event)
				if !ok || ce.Deposit == nil {
					return nil
				}
				if !ce.Deposit.From.Equal(wallet.Address()) || ce.Deposit.Nonce != tx.AuthInfo.SignerInfo[0].Nonce {
					return nil
				}
				return ce.Deposit
			})

			common.BroadcastTransaction(ctx, npw.ParaTime, conn, sigTx, nil)

			fmt.Printf("Waiting for deposit result...\n")

			ev := <-waitCh
			if ev == nil {
				cobra.CheckErr("Failed to wait for event.")
			}

			// Check for result.
			switch we := ev.(*consensusaccounts.DepositEvent); we.IsSuccess() {
			case true:
				fmt.Printf("Deposit succeeded.\n")
			case false:
				cobra.CheckErr(fmt.Errorf("Deposit failed with error code %d from module %s.",
					we.Error.Code,
					we.Error.Module,
				))
			}
		},
	}

	accountsWithdrawCmd = &cobra.Command{
		Use:   "withdraw <amount> [to]",
		Short: "Withdraw given amount of tokens into an account in the consensus layer",
		Args:  cobra.RangeArgs(1, 2),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.Global()
			npw := common.GetNPWSelection(cfg)
			txCfg := common.GetTransactionConfig()
			amount := args[0]
			var to string
			if len(args) >= 2 {
				to = args[1]
			}

			if npw.Wallet == nil {
				cobra.CheckErr("no wallets configured")
			}
			if npw.ParaTime == nil {
				cobra.CheckErr("no paratimes to withdraw from")
			}

			// When not in offline mode, connect to the given network endpoint.
			ctx := context.Background()
			var conn client.Connection
			if !txCfg.Offline {
				var err error
				conn, err = client.Connect(ctx, npw.Network)
				cobra.CheckErr(err)
			}

			// Resolve destination address when specified.
			var toAddr *types.Address
			if to != "" {
				var err error
				toAddr, err = config.ResolveAddress(npw.Network, to)
				cobra.CheckErr(err)
			}

			// Parse amount.
			// TODO: This should actually query the ParaTime (or config) to check what the consensus
			//       layer denomination is in the ParaTime. Assume NATIVE for now.
			amountBaseUnits, err := common.ParseParaTimeDenomination(npw.ParaTime, amount, types.NativeDenomination)
			cobra.CheckErr(err)

			// Prepare transaction.
			tx := consensusaccounts.NewWithdrawTx(nil, &consensusaccounts.Withdraw{
				To:     toAddr,
				Amount: *amountBaseUnits,
			})

			wallet := common.LoadWallet(cfg, npw.WalletName)
			sigTx, err := common.SignParaTimeTransaction(ctx, npw, wallet, conn, tx)
			cobra.CheckErr(err)

			if txCfg.Offline {
				common.PrintSignedTransaction(sigTx)
				return
			}

			decoder := conn.Runtime(npw.ParaTime).ConsensusAccounts
			waitCh := common.WaitForEvent(ctx, npw.ParaTime, conn, decoder, func(ev sdkClient.DecodedEvent) interface{} {
				ce, ok := ev.(*consensusaccounts.Event)
				if !ok || ce.Withdraw == nil {
					return nil
				}
				if !ce.Withdraw.From.Equal(wallet.Address()) || ce.Withdraw.Nonce != tx.AuthInfo.SignerInfo[0].Nonce {
					return nil
				}
				return ce.Withdraw
			})

			common.BroadcastTransaction(ctx, npw.ParaTime, conn, sigTx, nil)

			fmt.Printf("Waiting for withdraw result...\n")

			ev := <-waitCh
			if ev == nil {
				cobra.CheckErr("Failed to wait for event.")
			}
			we := ev.(*consensusaccounts.WithdrawEvent)

			// Check for result.
			switch we.IsSuccess() {
			case true:
				fmt.Printf("Withdraw succeeded.\n")
			case false:
				cobra.CheckErr(fmt.Errorf("Withdraw failed with error code %d from module %s.",
					we.Error.Code,
					we.Error.Module,
				))
			}
		},
	}

	accountsTransferCmd = &cobra.Command{
		Use:   "transfer <amount> <to>",
		Short: "Transfer given amount of tokens to a different account",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.Global()
			npw := common.GetNPWSelection(cfg)
			txCfg := common.GetTransactionConfig()
			amount, to := args[0], args[1]

			if npw.Wallet == nil {
				cobra.CheckErr("no wallets configured")
			}
			if npw.ParaTime == nil {
				// TODO: Support consensus layer transfers as well.
				cobra.CheckErr("no paratimes configured")
			}

			// When not in offline mode, connect to the given network endpoint.
			ctx := context.Background()
			var conn client.Connection
			if !txCfg.Offline {
				var err error
				conn, err = client.Connect(ctx, npw.Network)
				cobra.CheckErr(err)
			}

			// Resolve destination address.
			toAddr, err := config.ResolveAddress(npw.Network, to)
			cobra.CheckErr(err)

			// Parse amount.
			// TODO: This should actually query the ParaTime (or config) to check what the consensus
			//       layer denomination is in the ParaTime. Assume NATIVE for now.
			amountBaseUnits, err := common.ParseParaTimeDenomination(npw.ParaTime, amount, types.NativeDenomination)
			cobra.CheckErr(err)

			// Prepare transaction.
			tx := accounts.NewTransferTx(nil, &accounts.Transfer{
				To:     *toAddr,
				Amount: *amountBaseUnits,
			})

			wallet := common.LoadWallet(cfg, npw.WalletName)
			sigTx, err := common.SignParaTimeTransaction(ctx, npw, wallet, conn, tx)
			cobra.CheckErr(err)

			common.BroadcastTransaction(ctx, npw.ParaTime, conn, sigTx, nil)
		},
	}
)

func init() {
	accountsShowCmd.Flags().AddFlagSet(common.SelectorFlags)

	accountsAllowCmd.Flags().AddFlagSet(common.SelectorFlags)
	accountsAllowCmd.Flags().AddFlagSet(common.TransactionFlags)

	accountsDepositCmd.Flags().AddFlagSet(common.SelectorFlags)
	accountsDepositCmd.Flags().AddFlagSet(common.TransactionFlags)

	accountsWithdrawCmd.Flags().AddFlagSet(common.SelectorFlags)
	accountsWithdrawCmd.Flags().AddFlagSet(common.TransactionFlags)

	accountsTransferCmd.Flags().AddFlagSet(common.SelectorFlags)
	accountsTransferCmd.Flags().AddFlagSet(common.TransactionFlags)

	accountsCmd.AddCommand(accountsShowCmd)
	accountsCmd.AddCommand(accountsAllowCmd)
	accountsCmd.AddCommand(accountsDepositCmd)
	accountsCmd.AddCommand(accountsWithdrawCmd)
	accountsCmd.AddCommand(accountsTransferCmd)
}
