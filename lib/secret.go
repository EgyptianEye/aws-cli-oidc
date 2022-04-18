package lib

import (
	"encoding/json"
	"errors"
	"fmt"
)

type SecretStore interface {
	Load()
	Get(string) (*AWSCredentials, error)
	Save(string, string) error
	Clear() error
}

var secret SecretStore = defaultstore{}

func NewSecret(typ string) error {
	switch typ {
	case "keyring", "Keyring", "KEYRING":
		secret = NewKeyringStore()
	case "file", "File", "FILE":
		secret = NewFileStore()
	default:
		return errors.New("invalid type for credential store: " + typ)
	}
	return nil
}

func GetStoredAWSCredential(roleArn string) (*AWSCredentials, error) {
	secret.Load()
	cred, err := secret.Get(roleArn)
	if err != nil {
		return nil, err
	}
	if !cred.isValid() {
		return nil, errors.New("invalid token for " + roleArn)
	}
	return cred, nil
}

func StoreAWSCredential(roleArn string, cred *AWSCredentials) error {
	js, err := json.Marshal(cred)
	if err != nil {
		return fmt.Errorf("can't save secret due to the malformed data: %w", err)
	}
	return secret.Save(roleArn, string(js))
}

func Clear() error {
	return secret.Clear()
}

type defaultstore struct{}

func (defaultstore) Load() {}
func (defaultstore) Get(string) (*AWSCredentials, error) {
	return nil, errors.New("not implemented")
}
func (defaultstore) Save(string, string) error {
	return errors.New("not implemented")
}
func (defaultstore) Clear() error {
	return errors.New("not implemented")
}
