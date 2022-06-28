package lib

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func GetCredentialsWithOIDC(config *Config, it *idtoken) (*AWSCredentials, error) {
	role := pickRole(it.getRoles(config.RoleClaim), config.IAMRole)
	if role == "" {
		return nil, errors.New("no roles specified")
	}
	return assumeRoleWithOIDC(role, it.PreferredUsername, it.raw, config.SessionDuration)
}

func assumeRoleWithOIDC(role, sessName, rawIDToken string, sessDurantion int32) (*AWSCredentials, error) {
	ctx := context.TODO()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		panic("configuration error, " + err.Error())
	}
	input := &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String(role),
		RoleSessionName:  aws.String(sessName),
		WebIdentityToken: aws.String(rawIDToken),
		DurationSeconds:  aws.Int32(sessDurantion),
	}
	assumed, err := sts.NewFromConfig(cfg).AssumeRoleWithWebIdentity(ctx, input)
	if err != nil {
		return nil, err
	}
	result := &AWSCredentials{
		AWSAccessKey:    aws.ToString(assumed.Credentials.AccessKeyId),
		AWSSecretKey:    aws.ToString(assumed.Credentials.SecretAccessKey),
		AWSSessionToken: aws.ToString(assumed.Credentials.SessionToken),
		PrincipalARN:    aws.ToString(assumed.AssumedRoleUser.Arn),
		Expires:         assumed.Credentials.Expiration.Local(),
	}
	return result, nil
}

func pickRole(roles []string, configured string) string {
	if len(roles) > 0 {
		if configured != "" {
			found := false
			for _, role := range roles {
				if role == configured {
					found = true
					break
				}
			}
			if !found {
				fmt.Fprintf(os.Stderr, "role %s not found in ID token, will try though...\n", configured)
			}
			return configured
		} else {
			fmt.Fprintf(os.Stderr, "using %s from ID token as default role\n", roles[0])
			return roles[0]
		}
	}
	return configured
}
