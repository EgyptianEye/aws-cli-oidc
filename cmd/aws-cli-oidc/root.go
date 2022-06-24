package main

import (
	"github.com/openstandia/aws-cli-oidc/lib"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "aws-cli-oidc",
	Short: "CLI tool for retrieving AWS temporary credentials using OIDC provider",
	Long:  `CLI tool for retrieving AWS temporary credentials using OIDC provider`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		lib.Writeln(err.Error())
	}
}
