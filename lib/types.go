package lib

import (
	"encoding/json"
	"fmt"
	"time"
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
	return true
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
