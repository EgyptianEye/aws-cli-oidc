package lib

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func GetCredentialsWithOIDCV2(idToken, sessName, iamRoleArn string, durationInSeconds int32) (*AWSCredentials, error) {
	return loginToStsUsingIDTokenV2(idToken, sessName, iamRoleArn, durationInSeconds)
}

type STSAssumeRoleWithWebIdentityAPI interface {
	AssumeRoleWithWebIdentity(ctx context.Context,
		params *sts.AssumeRoleWithWebIdentityInput,
		optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
}

func assumeRoleWithWebIdentity(c context.Context, api STSAssumeRoleWithWebIdentityAPI, input *sts.AssumeRoleWithWebIdentityInput) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	return api.AssumeRoleWithWebIdentity(c, input)
}

func loginToStsUsingIDTokenV2(idToken, sessName, iamRoleArn string, durationInSeconds int32) (*AWSCredentials, error) {
	ctx := context.TODO()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		panic("configuration error, " + err.Error())
	}
	input := &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          &iamRoleArn,
		RoleSessionName:  &sessName,
		WebIdentityToken: &idToken,
		DurationSeconds:  &durationInSeconds,
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
