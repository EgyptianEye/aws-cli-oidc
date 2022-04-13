package lib

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"
)

func GetCredentialsWithOIDC(idToken, roleSessionName, iamRoleArn string, durationInSeconds int64) (*AWSCredentials, error) {
	return loginToStsUsingIDToken(idToken, roleSessionName, iamRoleArn, durationInSeconds)
}

func loginToStsUsingIDToken(idToken, roleSessionName, iamRoleArn string, durationInSeconds int64) (*AWSCredentials, error) {
	sess, err := session.NewSession()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create session")
	}

	svc := sts.New(sess)

	params := &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          &iamRoleArn,
		RoleSessionName:  &roleSessionName,
		WebIdentityToken: &idToken,
		DurationSeconds:  aws.Int64(durationInSeconds),
	}

	Writeln("Requesting AWS credentials using ID Token")

	resp, err := svc.AssumeRoleWithWebIdentity(params)
	if err != nil {
		return nil, errors.Wrap(err, "Error retrieving STS credentials using ID Token")
	}

	return &AWSCredentials{
		AWSAccessKey:    aws.StringValue(resp.Credentials.AccessKeyId),
		AWSSecretKey:    aws.StringValue(resp.Credentials.SecretAccessKey),
		AWSSessionToken: aws.StringValue(resp.Credentials.SessionToken),
		PrincipalARN:    aws.StringValue(resp.AssumedRoleUser.Arn),
		Expires:         resp.Credentials.Expiration.Local(),
	}, nil
}
