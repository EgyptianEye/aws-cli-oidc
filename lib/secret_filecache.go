package lib

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type FileStore struct {
	sync.RWMutex
	filepath string
	cred     map[string]*AWSCredentials
}

func NewFileStore() *FileStore {
	path := filepath.Join(ConfigPath(), "cache")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		f, err1 := os.Create(path)
		if err1 != nil {
			Exit(fmt.Errorf("cannot create secret file %s: %w", path, err1))
		}
		f.WriteString("{}\n")
		f.Close()
	}
	return &FileStore{filepath: path, cred: make(map[string]*AWSCredentials)}
}

func (sf *FileStore) Load() {
	sf.Lock()
	defer sf.Unlock()
	f, err := os.Open(sf.filepath)
	if err != nil {
		Exit(fmt.Errorf("cannot open secret file %s: %w", sf.filepath, err))
	}
	if err := json.NewDecoder(f).Decode(&sf.cred); err != nil {
		err1 := fmt.Errorf("warning: cannot decode secrect file %s: %w", sf.filepath, err)
		fmt.Fprintln(os.Stderr, err1)
	}
	f.Close()
}

func (sf *FileStore) Get(roleArn string) (*AWSCredentials, error) {
	sf.RLock()
	defer sf.RUnlock()
	c, ok := sf.cred[roleArn]
	if !ok {
		return nil, fmt.Errorf("credentials not found for %s", roleArn)
	}
	Writeln("Got credential from file store for %s", roleArn)
	return c, nil
}

func (sf *FileStore) Save(roleArn, cred string) error {
	sf.Lock()
	defer sf.Unlock()
	var c AWSCredentials
	if err := json.Unmarshal([]byte(cred), &c); err != nil {
		return fmt.Errorf("error unmarshalling credentials: %w", err)
	}
	sf.cred[roleArn] = &c
	f, err := os.Create(sf.filepath)
	if err != nil {
		return fmt.Errorf("cannot save credentials for %s: %w", roleArn, err)
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(sf.cred); err != nil {
		return fmt.Errorf("cannot save credentials for %s: %w", roleArn, err)
	}
	return nil
}

func (sf *FileStore) Clear() error {
	sf.Lock()
	defer sf.Unlock()
	for k := range sf.cred {
		delete(sf.cred, k)
	}
	return os.Remove(sf.filepath)
}
