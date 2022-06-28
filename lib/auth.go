package lib

import (
	"fmt"
)

func Authenticate(config *Config) (*AWSCredentials, error) {
	it, err := codeFlow(config)
	if err != nil {
		return nil, fmt.Errorf("failed to login the OIDC provider: %w", err)
	}
	Writeln("login successful!")
	Traceln("ID token: %s", it.raw)
	var awsCreds *AWSCredentials
	awsCreds, err = GetCredentialsWithOIDC(config, it)
	if err != nil {
		return nil, fmt.Errorf("failed to get aws credentials with OIDC: %w", err)
	}
	return awsCreds, nil
}
