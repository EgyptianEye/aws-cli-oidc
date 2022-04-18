package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/openstandia/aws-cli-oidc/lib"
	"github.com/spf13/cobra"
)

var getCredCmd = &cobra.Command{
	Use:   "get-cred <OIDC provider name>",
	Short: "Get AWS credentials and out to stdout",
	Long:  `Get AWS credentials and out to stdout through your OIDC provider authentication.`,
	Run:   getCred,
}

func init() {
	getCredCmd.Flags().StringP("provider", "p", "", "OIDC provider name")
	getCredCmd.Flags().StringP("role", "r", "", "Override default assume role ARN")
	getCredCmd.Flags().Int64P("max-duration", "d", 0, "Override default max session duration, in seconds, of the role session [900-43200]")
	getCredCmd.Flags().StringP("use-secret", "s", "", "Store AWS credentials in [keyring] or [file], then load it without re-authentication")
	getCredCmd.Flags().BoolP("json", "j", false, "Print the credential as JSON format")
	rootCmd.AddCommand(getCredCmd)
}

func getCred(cmd *cobra.Command, args []string) {
	providerName, _ := cmd.Flags().GetString("provider")
	if providerName == "" {
		lib.Exit(errors.New("the OIDC provider name is required"))
	}
	roleArn, _ := cmd.Flags().GetString("role")
	maxDurationSeconds, _ := cmd.Flags().GetInt64("max-duration")
	useSecret, _ := cmd.Flags().GetString("use-secret")
	asJson, _ := cmd.Flags().GetBool("json")

	lib.Exit(output(asJson)(authenticate(useSecret, providerName, roleArn, maxDurationSeconds)))
}

func output(json bool) func(*lib.AWSCredentials, error) error {
	return func(cred *lib.AWSCredentials, err error) error {
		if err != nil {
			return err
		}
		if json {
			js, err := cred.JSON()
			if err == nil {
				fmt.Println(js)
			}
			return err
		}
		exp, _ := cred.Export()
		fmt.Fprintf(os.Stderr, "\n%s", exp)
		return nil
	}
}

func authenticate(store, provider, roleArn string, maxDurationSeconds int64) (cred *lib.AWSCredentials, err error) {
	useSecret := lib.InitializeSecret(store, provider) == nil
	if useSecret {
		cred, err = lib.GetStoredAWSCredential(roleArn)
		if err == nil {
			return
		}
	}
	client, err := lib.CheckInstalled(provider)
	if err != nil {
		lib.Exit(fmt.Errorf("failed to login via OIDC provider %s", provider))
	}
	cred, err = lib.Authenticate(client, roleArn, maxDurationSeconds)
	if err == nil && useSecret {
		lib.StoreAWSCredential(roleArn, cred)
		lib.Write("The AWS credentials has been saved in " + store)
	}
	return
}
