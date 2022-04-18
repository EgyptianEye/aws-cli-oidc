package main

import (
	"fmt"

	"github.com/openstandia/aws-cli-oidc/lib"
	"github.com/spf13/cobra"
)

var clearSecretCmd = &cobra.Command{
	Use:   "clear-secret",
	Short: "Clear secret store that saves AWS credentials",
	Long:  `Clear secret store that saves AWS credentials.`,
	Run:   clearSecret,
}

func init() {
	clearSecretCmd.Flags().StringP("provider", "p", "", "OIDC provider name")
	clearSecretCmd.Flags().StringP("use-secret", "s", "", "AWS credentials store: [keyring] or [file]")
	rootCmd.AddCommand(clearSecretCmd)
}

func clearSecret(cmd *cobra.Command, args []string) {
	provider, _ := cmd.Flags().GetString("provider")
	secret, _ := cmd.Flags().GetString("use-secret")
	if provider == "" || secret == "" {
		lib.Exit(cmd.Usage())
	}
	if err := lib.InitializeSecret(secret, provider); err != nil {
		lib.Exit(fmt.Errorf("cannot initialize store: %w", err))
	}
	if err := lib.ClearSecret(); err != nil {
		lib.Exit(fmt.Errorf("failed to clear the secret store: %w", err))
	}
	lib.Writeln("The secret store has been cleared")
}
