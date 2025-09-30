package keyring

import (
	"encoding/json"
	"errors"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// storage represents a type that combines credentialStorage and keyValueStorage.
// It is used to store credentials and key-value pairs.
type storage struct {
	CredentialStorage credentialStorage `yaml:"credential_storage"`
	KeyValueStorage   keyValueStorage   `yaml:"key_value_storage"`
}

type credentialStorage []CredentialsItem
type keyValueStorage []KeyValueItem

type dataStoreYaml struct {
	file   CredentialsFile
	data   storage
	loaded bool
}

func (s *dataStoreYaml) load() error {
	if s.loaded {
		return nil
	}

	err := s.file.Open(os.O_RDONLY, 0)
	if os.IsNotExist(err) {
		// The keyring is new.
		s.loaded = true
		return nil
	} else if err != nil {
		return err
	}
	defer s.file.Close()
	if err = s.file.Unlock(false); err != nil {
		return err
	}
	dec := yaml.NewDecoder(s.file)
	var strg storage
	err = dec.Decode(&strg)
	if err != nil {
		if strings.Contains(err.Error(), ErrKeyringMalformed.Error()) {
			// The keyring is malformed, treat it as new.
			s.file.Lock()
			s.loaded = true
			return nil
		}
		return err
	}
	s.data = strg
	s.loaded = true
	return nil
}

// GetUrls implements DataStore interface.
func (s *dataStoreYaml) GetUrls() ([]string, error) {
	var result []string
	if err := s.load(); err != nil {
		return result, err
	}

	for i := 0; i < len(s.data.CredentialStorage); i++ {
		result = append(result, s.data.CredentialStorage[i].URL)
	}

	return result, nil
}

// GetKeys implements DataStore interface.
func (s *dataStoreYaml) GetKeys() ([]string, error) {
	var result []string
	if err := s.load(); err != nil {
		return result, err
	}

	for i := 0; i < len(s.data.KeyValueStorage); i++ {
		result = append(result, s.data.KeyValueStorage[i].Key)
	}

	return result, nil
}

// GetForURL implements DataStore interface.
func (s *dataStoreYaml) GetForURL(url string) (CredentialsItem, error) {
	if err := s.load(); err != nil {
		return CredentialsItem{}, err
	}
	for i := 0; i < len(s.data.CredentialStorage); i++ {
		if s.data.CredentialStorage[i].URL == url {
			return s.data.CredentialStorage[i], nil
		}
	}
	return CredentialsItem{}, ErrNotFound
}

// GetForKey implements DataStore interface.
func (s *dataStoreYaml) GetForKey(key string) (KeyValueItem, error) {
	if err := s.load(); err != nil {
		return KeyValueItem{}, err
	}
	for i := 0; i < len(s.data.KeyValueStorage); i++ {
		if s.data.KeyValueStorage[i].Key == key {
			return s.data.KeyValueStorage[i], nil
		}
	}

	return KeyValueItem{}, ErrNotFound
}

// AddItem implements DataStore interface.
func (s *dataStoreYaml) AddItem(item SecretItem) error {
	if item.isEmpty() {
		return ErrEmptyFields
	}

	if err := s.load(); err != nil {
		return err
	}

	switch dataItem := item.(type) {
	case CredentialsItem:
		urlIdx := -1
		for i := 0; i < len(s.data.CredentialStorage); i++ {
			if s.data.CredentialStorage[i].URL == dataItem.URL {
				urlIdx = i
				break
			}
		}
		if urlIdx != -1 {
			s.data.CredentialStorage[urlIdx] = dataItem
		} else {
			s.data.CredentialStorage = append(s.data.CredentialStorage, dataItem)
		}
	case KeyValueItem:
		urlIdx := -1
		for i := 0; i < len(s.data.KeyValueStorage); i++ {
			if s.data.KeyValueStorage[i].Key == dataItem.Key {
				urlIdx = i
				break
			}
		}
		if urlIdx != -1 {
			s.data.KeyValueStorage[urlIdx] = dataItem
		} else {
			s.data.KeyValueStorage = append(s.data.KeyValueStorage, dataItem)
		}
	default:
		panic(errors.New("unknown storage type"))
	}

	return nil
}

// RemoveByURL implements DataStore interface.
func (s *dataStoreYaml) RemoveByURL(url string) error {
	if err := s.load(); err != nil {
		return err
	}
	for i := 0; i < len(s.data.CredentialStorage); i++ {
		if s.data.CredentialStorage[i].URL == url {
			s.data.CredentialStorage = append(s.data.CredentialStorage[:i], s.data.CredentialStorage[i+1:]...)
			return nil
		}
	}
	return ErrNotFound
}

// RemoveByKey implements DataStore interface.
func (s *dataStoreYaml) RemoveByKey(key string) error {
	if err := s.load(); err != nil {
		return err
	}
	for i := 0; i < len(s.data.KeyValueStorage); i++ {
		if s.data.KeyValueStorage[i].Key == key {
			s.data.KeyValueStorage = append(s.data.KeyValueStorage[:i], s.data.KeyValueStorage[i+1:]...)
			return nil
		}
	}
	return ErrNotFound
}

// CleanStorage implements DataStore interface.
func (s *dataStoreYaml) CleanStorage(item SecretItem) error {
	if err := s.load(); err != nil {
		return err
	}

	switch item.(type) {
	case CredentialsItem:
		s.data.CredentialStorage = []CredentialsItem{}
	case KeyValueItem:
		s.data.KeyValueStorage = []KeyValueItem{}
	default:
		panic(errors.New("unknown storage type"))
	}

	return nil
}

// Exists implements DataStore, checks if keyring exists in persistent storage.
func (s *dataStoreYaml) Exists() bool {
	ageStorage, ok := s.file.(*ageFile)
	if !ok {
		panic("impossible type assertion")
	}

	info, err := os.Stat(ageStorage.file.fname)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// Save implements DataStore interface.
func (s *dataStoreYaml) Save() error {
	err := s.file.Open(os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer s.file.Close()
	if err = s.file.Unlock(true); err != nil {
		return err
	}
	enc := yaml.NewEncoder(s.file)
	return enc.Encode(s.data)
}

// Destroy implements DataStore interface.
func (s *dataStoreYaml) Destroy() error {
	return s.file.Remove()
}

func parseFromString(format, value string) (interface{}, error) {
	if format == "string" || value == "" {
		return value, nil
	}

	var parsed interface{}
	var err error
	switch format {
	case "json":
		err = json.Unmarshal([]byte(value), &parsed)
	case "yaml":
		err = yaml.Unmarshal([]byte(value), &parsed)
	default:
		panic("unsupported format: " + format)
	}

	return parsed, err
}
