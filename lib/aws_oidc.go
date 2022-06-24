package lib

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func GetCredentialsWithOIDC(config *Config, it *idtoken) (*AWSCredentials, error) {
	if len(it.Roles) > 0 {
		if config.IAMRole != "" {
			found := false
			for _, role := range it.Roles {
				if role == config.IAMRole {
					found = true
					break
				}
			}
			if !found {
				fmt.Fprintf(os.Stderr, "Role \"%s\" not found in ID token, will try though...\n", config.IAMRole)
			}
		} else {
			fmt.Fprintf(os.Stderr, "Using %s from ID token as default role\n", it.Roles[0])
			config.IAMRole = it.Roles[0]
		}
	}
	return loginToStsUsingIDTokenV2(config, it)
}

type STSAssumeRoleWithWebIdentityAPI interface {
	AssumeRoleWithWebIdentity(ctx context.Context,
		params *sts.AssumeRoleWithWebIdentityInput,
		optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
}

func assumeRoleWithWebIdentity(c context.Context, api STSAssumeRoleWithWebIdentityAPI, input *sts.AssumeRoleWithWebIdentityInput) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	return api.AssumeRoleWithWebIdentity(c, input)
}

func loginToStsUsingIDTokenV2(c *Config, it *idtoken) (*AWSCredentials, error) {
	ctx := context.TODO()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		panic("configuration error, " + err.Error())
	}
	input := &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          &c.IAMRole,
		RoleSessionName:  &it.PreferredUsername,
		WebIdentityToken: &it.raw,
		DurationSeconds:  &c.SessionDuration,
	}
	assumed, err := assumeRoleWithWebIdentity(ctx, sts.NewFromConfig(cfg), input)
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
