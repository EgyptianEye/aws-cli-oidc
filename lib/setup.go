package lib

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	input "github.com/natsukagami/go-input"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

const NoDepKey string = ""

type setup struct {
	key    string
	dep    string
	getter func(ui *input.UI) (string, error)
}

var steps []setup = []setup{
	{IdP, NoDepKey, func(ui *input.UI) (string, error) {
		return ui.Ask("Identity provider name:", &input.Options{
			Required: true,
			Loop:     true,
		})
	}},
	{OIDC_PROVIDER_METADATA_URL, NoDepKey, func(ui *input.UI) (string, error) {
		return ui.Ask("OIDC provider metadata URL (https://your-oidc-provider/.well-known/openid-configuration):", &input.Options{
			Required: true,
			Loop:     true,
		})
	}},
	{OIDC_AUTHENTICATION_REQUEST_ADDITIONAL_QUERY, NoDepKey, func(ui *input.UI) (string, error) {
		return ui.Ask("Additional query for OIDC authentication request (Default: none):", &input.Options{
			Default:  "",
			Required: false,
		})
	}},
	{SUCCESSFUL_REDIRECT_URL, NoDepKey, func(ui *input.UI) (string, error) {
		return ui.Ask("Successful redirect URL (Default: none):", &input.Options{
			Default:  "",
			Required: false,
		})
	}},
	{FAILURE_REDIRECT_URL, NoDepKey, func(ui *input.UI) (string, error) {
		return ui.Ask("Failure redirect URL (Default: none):", &input.Options{
			Default:  "",
			Required: false,
		})
	}},
	{CLIENT_ID, NoDepKey, func(ui *input.UI) (string, error) {
		return ui.Ask("Client ID which is registered in the OIDC provider:", &input.Options{
			Required: true,
			Loop:     true,
		})
	}},
	{CLIENT_SECRET, NoDepKey, func(ui *input.UI) (string, error) {
		return ui.Ask("Client secret which is registered in the OIDC provider (Default: none):", &input.Options{
			Default:  "",
			Required: false,
		})
	}},
	{INSECURE_SKIP_VERIFY, NoDepKey, func(ui *input.UI) (string, error) {
		return ui.Ask("Insecure mode for HTTPS access (Default: false):", &input.Options{
			Default:  "false",
			Required: false,
			ValidateFunc: func(s string) error {
				if strings.ToLower(s) != "false" || strings.ToLower(s) != "true" {
					return errors.New("Input must be true or false")
				}
				return nil
			},
		})
	}},
	{AWS_FEDERATION_TYPE, NoDepKey, func(ui *input.UI) (string, error) {
		return ui.Ask(fmt.Sprintf("Choose type of AWS federation [%s/%s]:", AWS_FEDERATION_TYPE_OIDC, AWS_FEDERATION_TYPE_SAML2), &input.Options{
			Required: true,
			Loop:     true,
			ValidateFunc: func(s string) error {
				if s != AWS_FEDERATION_TYPE_SAML2 && s != AWS_FEDERATION_TYPE_OIDC {
					return errors.New(fmt.Sprintf("Input must be '%s' or '%s'", AWS_FEDERATION_TYPE_OIDC, AWS_FEDERATION_TYPE_SAML2))
				}
				return nil
			},
		})
	}},
	{MAX_SESSION_DURATION_SECONDS, NoDepKey, func(ui *input.UI) (string, error) {
		return ui.Ask("The max session duration, in seconds, of the role session [900-43200] (Default: 3600):", &input.Options{
			Default:  "3600",
			Required: true,
			Loop:     true,
			ValidateFunc: func(s string) error {
				i, err := strconv.ParseInt(s, 10, 64)
				if err != nil || i < 900 || i > 43200 {
					return errors.New("Input must be 900-43200")
				}
				return nil
			},
		})
	}},
	{IAM_ROLE_ARN, NoDepKey, func(ui *input.UI) (string, error) {
		return ui.Ask("The default IAM Role ARN when you have multiple roles, as arn:aws:iam::<account-id>:role/<role-name> (Default: none):", &input.Options{
			Default:  "",
			Required: false,
			Loop:     true,
			ValidateFunc: func(s string) error {
				if s == "" {
					return nil
				}
				arn := strings.Split(s, ":")
				if len(arn) == 6 {
					if arn[0] == "arn" && strings.HasPrefix(arn[1], "aws") && arn[2] == "iam" && arn[3] == "" && strings.HasPrefix(arn[5], "role/") {
						return nil
					}
				}
				return errors.New("Input must be IAM Role ARN")
			},
		})
	}},
	{CLIENT_AUTH_CERT, NoDepKey, func(ui *input.UI) (string, error) {
		return ui.Ask("A PEM encoded certificate file which is required to access the OIDC provider with MTLS (Default: none):", &input.Options{
			Default:  "",
			Required: false,
		})
	}},
	{CLIENT_AUTH_KEY, CLIENT_AUTH_CERT, func(ui *input.UI) (string, error) {
		return ui.Ask("A PEM encoded private key file which is required to access the OIDC provider with MTLS (Default: none):", &input.Options{
			Required: true,
			Loop:     true,
		})
	}},
	{CLIENT_AUTH_CA, CLIENT_AUTH_CERT, func(ui *input.UI) (string, error) {
		return ui.Ask("A PEM encoded CA's certificate file which is required to access the OIDC provider with MTLS (Default: none):", &input.Options{
			Required: true,
			Loop:     true,
		})
	}},
}

func RunSetup(ui *input.UI) {
	if ui == nil {
		ui = input.DefaultUI()
	}
	config := make(map[string]interface{})

	for _, step := range steps {
		if v, ok := config[step.dep]; step.dep != NoDepKey && (!ok || v == "") {
			// has dependent key but not found (default value treat as unset)
			// XXX: use func to verify
			continue
		}
		value, err := step.getter(ui)
		if err != nil {
			Writeln("error setting up: %s", err)
			return
		}
		config[step.key] = value
	}

	if config[AWS_FEDERATION_TYPE] == AWS_FEDERATION_TYPE_OIDC {
		oidcSetup(ui, config)
	} else if config[AWS_FEDERATION_TYPE] == AWS_FEDERATION_TYPE_SAML2 {
		saml2Setup(ui, config)
	}

	k := config[IdP].(string)
	if c := viper.Sub(k); c != nil {
		c.MergeConfigMap(config)
	} else {
		viper.Set(k, config)
	}

	os.MkdirAll(ConfigPath(), 0700)
	configPath := filepath.Join(ConfigPath(), "config.yaml")
	viper.SetConfigFile(configPath)

	if err := viper.WriteConfig(); err != nil {
		Writeln("Failed to write %s", configPath)
		Exit(err)
	}

	Writeln("Saved %s", configPath)
}

// runSetup is a special case, which provider is already supplied
func runSetup(ui *input.UI, provider string) {
	if ui == nil {
		ui = input.DefaultUI()
	}
	config := make(map[string]interface{})
	for _, step := range steps[1:] { // skip IdP setup
		if v, ok := config[step.dep]; step.dep != NoDepKey && (!ok || v == "") {
			continue
		}
		value, err := step.getter(ui)
		if err != nil {
			Writeln("error setting up: %s", err)
			return
		}
		config[step.key] = value
	}
	config[IdP] = provider
	switch config[AWS_FEDERATION_TYPE] {
	case AWS_FEDERATION_TYPE_OIDC:
		oidcSetup(ui, config)
	case AWS_FEDERATION_TYPE_SAML2:
		saml2Setup(ui, config)
	}
	if c := viper.Sub(provider); c != nil {
		c.MergeConfigMap(config)
	} else {
		viper.Set(provider, config)
	}
	os.MkdirAll(ConfigPath(), 0700)
	configPath := filepath.Join(ConfigPath(), "config.yaml")
	viper.SetConfigFile(configPath)
	if err := viper.WriteConfig(); err != nil {
		Writeln("Failed to write %s", configPath)
		Exit(err)
	}
	Writeln("Saved %s for %s", configPath, provider)
}

func oidcSetup(ui *input.UI, config map[string]interface{}) {
	awsRoleSessionName, _ := ui.Ask("AWS federation roleSessionName:", &input.Options{
		Required: true,
		Loop:     true,
	})
	config[AWS_FEDERATION_ROLE_SESSION_NAME] = awsRoleSessionName
}

func saml2Setup(ui *input.UI, config map[string]interface{}) {
	answer, _ := ui.Ask(`Select the subject token type to exchange for SAML2 assertion:
	1. Access Token (urn:ietf:params:oauth:token-type:access_token)
	2. ID Token (urn:ietf:params:oauth:token-type:id_token)
  `, &input.Options{
		Required: true,
		Loop:     true,
		ValidateFunc: func(s string) error {
			if s != "1" && s != "2" {
				return errors.New("Input must be number")
			}
			return nil
		},
	})
	var subjectTokenType string
	if answer == "1" {
		subjectTokenType = TOKEN_TYPE_ACCESS_TOKEN
	} else if answer == "2" {
		subjectTokenType = TOKEN_TYPE_ID_TOKEN
	}
	config[OIDC_PROVIDER_TOKEN_EXCHANGE_SUBJECT_TOKEN_TYPE] = subjectTokenType

	audience, _ := ui.Ask("Audience for token exchange:", &input.Options{
		Required: true,
		Loop:     true,
	})
	config[OIDC_PROVIDER_TOKEN_EXCHANGE_AUDIENCE] = audience
}

func setupOIDCProvider(name string) {
	ui := input.DefaultUI()
	answer, err := ui.Ask(
		fmt.Sprintf("Do you want to setup the configuration for identity provider \"%s\"? [Y/n]", name),
		&input.Options{
			Default: "Y",
			Loop:    true,
			ValidateFunc: func(s string) error {
				if s != "Y" && s != "n" {
					return errors.New("Input must be Y or n")
				}
				return nil
			},
		},
	)
	switch {
	case err != nil:
		Exit(fmt.Errorf("failed to initialize setup: %w", err))
	case answer == "n":
		Exit(nil)
	}
	runSetup(ui, name)
}
