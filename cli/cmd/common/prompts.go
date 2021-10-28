package common

import (
	"github.com/AlecAivazis/survey/v2"
	"github.com/spf13/cobra"
)

var PromptPassphrase = &survey.Password{
	Message: "Passphrase:",
}

// Confirm asks the user for confirmation and aborts when rejected.
func Confirm(msg, abortMsg string) {
	// TODO: Support flag for skipping confirmations.

	var proceed bool
	err := survey.AskOne(&survey.Confirm{Message: msg}, &proceed)
	cobra.CheckErr(err)
	if !proceed {
		cobra.CheckErr(abortMsg)
	}
}
