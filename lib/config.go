//go:build go1.12

package lib

import (
	"errors"
	"os"
	"strconv"

	"github.com/spf13/viper"
)

const OIDC_PROVIDER_METADATA_URL = "oidc_provider_metadata_url"
const OIDC_AUTHENTICATION_REQUEST_ADDITIONAL_QUERY = "oidc_authentication_request_additional_query"
const SUCCESSFUL_REDIRECT_URL = "successful_redirect_url"
const FAILURE_REDIRECT_URL = "failure_redirect_url"
const CLIENT_ID = "client_id"
const CLIENT_SECRET = "client_secret"
const CLIENT_AUTH_CERT = "client_auth_cert"
const CLIENT_AUTH_KEY = "client_auth_key"
const CLIENT_AUTH_CA = "client_auth_ca"
const INSECURE_SKIP_VERIFY = "insecure_skip_verify"
const AWS_FEDERATION_TYPE = "aws_federation_type"
const MAX_SESSION_DURATION_SECONDS = "max_session_duration_seconds"
const IAM_ROLE_ARN = "iam_role_arn"
const IdP = "identity_provider"

// OIDC config
const AWS_FEDERATION_ROLE_SESSION_NAME = "aws_federation_role_session_name"

// SAML config
const OIDC_PROVIDER_TOKEN_EXCHANGE_AUDIENCE = "oidc_provider_token_exchange_audience"
const OIDC_PROVIDER_TOKEN_EXCHANGE_SUBJECT_TOKEN_TYPE = "oidc_provider_token_exchange_subject_token_type" // Only support saml2

// OAuth 2.0 Token Exchange
const TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
const TOKEN_TYPE_ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token"

// Federation Type
const AWS_FEDERATION_TYPE_OIDC = "oidc"
const AWS_FEDERATION_TYPE_SAML2 = "saml2"

var configdir string

func ConfigPath() string {
	if configdir != "" {
		return configdir
	}
	path := os.Getenv("AWS_CLI_OIDC_CONFIG")
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			Exit(err)
		}
		path = home + "/.aws-cli-oidc"
	}
	configdir = path
	return configdir
}

func MergedConfig(provider, roleArn, maxSessionDuration string) *viper.Viper {
	if viper.Sub(provider) == nil {
		setupOIDCProvider(provider)
	}
	conf := viper.Sub(provider)
	if conf == nil {
		Exit(errors.New("failed to setup configuration"))
	}
	if roleArn != "" {
		conf.Set(IAM_ROLE_ARN, roleArn)
	}
	conf.SetDefault(MAX_SESSION_DURATION_SECONDS, "3600")
	if i, err := strconv.ParseInt(maxSessionDuration, 10, 64); err == nil && i >= 900 && i <= 43200 {
		conf.Set(MAX_SESSION_DURATION_SECONDS, maxSessionDuration)
	}
	return conf
}
