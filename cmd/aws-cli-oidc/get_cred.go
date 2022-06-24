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
	var a lib.CmdArgs
	a.IdP, _ = cmd.Flags().GetString("provider")
	a.PreferedRole, _ = cmd.Flags().GetString("role")
	a.SessionDuration, _ = cmd.Flags().GetInt32("max-duration")
	a.Secret, _ = cmd.Flags().GetString("use-secret")
	asJson, _ := cmd.Flags().GetBool("json")

	lib.Exit(output(asJson)(authenticate(a)))
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

func authenticate(args lib.CmdArgs) (cred *lib.AWSCredentials, err error) {
	useSecret := lib.InitializeSecret(args.Secret, args.IdP) == nil
	config, err := lib.RuntimeConfig(args)
	if err != nil {
		lib.Exit(err)
	}
	if useSecret && config.IAMRole == "" {
		lib.Write("Secret \"%s\" has been configured but disabled, because no roles were specified.\n(Behaviors will depend on the 'roles' claim in ID tokens, which is subject to change.)\n", args.Secret)
	}
	if useSecret && config.IAMRole != "" {
		cred, err = lib.GetStoredAWSCredential(config.IAMRole)
		if err == nil {
			return
		}
	}
	cred, err = lib.Authenticate(config)
	if err == nil && useSecret && config.IAMRole != "" {
		lib.StoreAWSCredential(config.IAMRole, cred)
		lib.Write("The AWS credentials has been saved in " + args.Secret)
	}
	return
}
