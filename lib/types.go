package lib

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

type AWSCredentials struct {
	Version         int
	AWSAccessKey    string    `json:"AccessKeyId"`
	AWSSecretKey    string    `json:"SecretAccessKey"`
	AWSSessionToken string    `json:"SessionToken"`
	PrincipalARN    string    `json:"-"`
	Expires         time.Time `json:"Expiration"`
}

func (c *AWSCredentials) isValid() bool {
	if c == nil {
		return false
	}
	if !c.Expires.IsZero() && time.Now().After(c.Expires) {
		return false
	}
	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		Writeln("Failed to create aws client session")
		Exit(err)
	}
	creds := credentials.NewStaticCredentialsFromCreds(credentials.Value{
		AccessKeyID:     c.AWSAccessKey,
		SecretAccessKey: c.AWSSecretKey,
		SessionToken:    c.AWSSessionToken,
	})
	svc := sts.New(sess, aws.NewConfig().WithCredentials(creds))
	input := &sts.GetCallerIdentityInput{}
	_, err = svc.GetCallerIdentity(input)
	if err != nil {
		Writeln("The previous credential isn't valid, need re-authentication")
	}
	return err == nil
}

func (c *AWSCredentials) JSON() (string, error) {
	c.Version = 1
	bs, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("unexpected AWS credential response: %w", err)
	}
	return string(bs), nil
}

func (c *AWSCredentials) Export() (string, error) {
	return export(map[string]string{
		"AWS_ACCESS_KEY_ID":     c.AWSAccessKey,
		"AWS_SECRET_ACCESS_KEY": c.AWSSecretKey,
		"AWS_SESSION_TOKEN":     c.AWSSessionToken,
	}), nil
}

type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	IDToken          string `json:"id_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
}

type LoginParams struct {
	ResponseType string `url:"response_type,omitempty"`
	ClientId     string `url:"client_id,omitempty"`
	RedirectUri  string `url:"redirect_uri,omitempty"`
	Display      string `url:"display,omitempty"`
	Scope        string `url:"scope,omitempty"`
}
