//go:build go1.12

package lib

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	SessionDuration int32    `json:"session_duration"`
	ClientID        string   `json:"client_id"`
	ClientSecret    string   `json:"client_secret"`
	IAMRole         string   `json:"iam_role"`
	RoleClaim       string   `json:"role_claim"`
	MetaURL         string   `json:"meta"`
	Scopes          []string `json:"scopes"`
}

type CmdArgs struct {
	SessionDuration int32
	IdP             string
	PreferedRole    string
	Secret          string
}

var configpath string

func ConfigPath() string {
	if configpath != "" {
		return configpath
	}
	path := os.Getenv("AWS_CLI_OIDC_CONFIG")
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			Exit(err)
		}
		path = filepath.Join(home, ".aws-cli-oidc")
	}
	configpath = path
	return configpath
}

func RuntimeConfig(args CmdArgs) (*Config, error) {
	f, err := os.Open(filepath.Join(ConfigPath(), "config.json"))
	if err != nil {
		if os.IsNotExist(err) {
			Exit(fmt.Errorf("%w - please create your own configuration", err))
		}
		return nil, err
	}
	defer f.Close()
	var idp map[string]Config
	if err = json.NewDecoder(f).Decode(&idp); err != nil {
		return nil, err
	}
	if cfg, ok := idp[args.IdP]; ok {
		if args.PreferedRole != "" {
			cfg.IAMRole = args.PreferedRole
		}
		if args.SessionDuration != 0 {
			cfg.SessionDuration = args.SessionDuration
		}
		return &cfg, nil
	}
	return nil, fmt.Errorf("identity provider not found: %s", args.IdP)
}
