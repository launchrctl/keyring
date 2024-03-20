package keyring

import (
	"errors"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/launchrctl/launchr"
)

const defaultFileYaml = "keyring.yaml"

var (
	ErrNotFound         = errors.New("item not found")            // ErrNotFound if an item was not found
	ErrEmptyFields      = errors.New("item can't be empty")       // ErrEmptyFields if fields are empty
	ErrEmptyPass        = errors.New("passphrase can't be empty") // ErrEmptyPass if a passphrase is empty
	ErrKeyringMalformed = errors.New("the keyring is malformed")  // ErrKeyringMalformed when keyring can't be read.
)

// Storage represents a type that combines CredentialStorage and KeyValueStorage.
// It is used to store credentials and key-value pairs.
type Storage struct {
	CredentialStorage `yaml:"credential_storage"`
	KeyValueStorage   `yaml:"key_value_storage"`
}

// CredentialStorage represents a type used to store credentials.
// It contains an array of CredentialsItem structs.
type CredentialStorage struct {
	CredentialItems []CredentialsItem `yaml:"credentials"`
}

// KeyValueStorage represents a type that is used to store key-value pairs.
// It contains a slice of KeyValueItem which represents each key-value pair.
type KeyValueStorage struct {
	KeyValueItems []KeyValueItem `yaml:"key_values"`
}

// StorageItem is an interface that represents an item stored in a Storage.
// It should have an isEmpty() method to check if the item is empty.
// It is used in the DataStore interface for adding and manipulating items.
type StorageItem interface {
	isEmpty() bool
}

// CredentialsItem stores credentials.
type CredentialsItem struct {
	URL      string `yaml:"url"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

func (i CredentialsItem) isEmpty() bool {
	return i.URL == "" || i.Username == "" || i.Password == ""
}

// KeyValueItem stores key-value pair.
type KeyValueItem struct {
	Key   string `yaml:"key"`
	Value string `yaml:"value"`
}

func (i KeyValueItem) isEmpty() bool {
	return i.Key == "" || i.Value == ""
}

// DataStore provides password storage functionality.
type DataStore interface {
	// GetForURL returns a credentials item by a URL.
	// Error is returned if either the keyring could not be unlocked
	// Error ErrNotFound if the credentials were not found.
	GetForURL(url string) (CredentialsItem, error)
	// GetForKey returns a key-value item by a key.
	// Error is returned if either the keyring could not be unlocked
	// Error ErrNotFound if the key was not found.
	GetForKey(key string) (KeyValueItem, error)
	// AddItem adds a new credential item.
	// Error is returned if the vault couldn't be unlocked.
	// Error ErrEmptyFields is returned if item is empty.
	AddItem(StorageItem) error
	// RemoveByURL deletes an item by url.
	// Error is returned if the vault couldn't be unlocked.
	// Error ErrNotFound if the credentials were not found.
	RemoveByURL(url string) error
	// RemoveByKey deletes an item by key.
	// Error is returned if the vault couldn't be unlocked.
	// Error ErrNotFound if the credentials were not found.
	RemoveByKey(key string) error
	// cleanStorage cleanups storage (credentials or key-value).
	// Error is returned if the vault couldn't be unlocked.
	cleanStorage(item StorageItem) error
	// Save saves the keyring to the persistent storage.
	Save() error
	// Destroy removes the keyring from the persistent storage.
	Destroy() error
}

// Keyring is a launchr.Service providing password store functionality.
type Keyring interface {
	launchr.Service
	DataStore
}

type keyringService struct {
	fname string
	store DataStore
	cfg   launchr.Config
}

func newKeyringService(cfg launchr.Config) Keyring {
	return &keyringService{
		fname: cfg.Path(defaultFileYaml),
		cfg:   cfg,
	}
}

// ServiceInfo implements launchr.Service interface.
func (k *keyringService) ServiceInfo() launchr.ServiceInfo {
	return launchr.ServiceInfo{}
}

func (k *keyringService) defaultStore() (DataStore, error) {
	if k.store != nil {
		return k.store, nil
	}
	var askPass AskPass
	if passphrase != "" {
		askPass = AskPassConstFlow(passphrase)
	} else {
		askPass = AskPassWithTerminal{}
	}
	// @todo parse header to know if it's encrypted or not.
	// @todo do not encrypt if the passphrase is not provided.
	k.store = &dataStoreYaml{file: newAgeFile(k.fname, askPass)}
	return k.store, nil
}

// GetForURL implements DataStore interface. Uses service default store.
func (k *keyringService) GetForURL(url string) (CredentialsItem, error) {
	s, err := k.defaultStore()
	if err != nil {
		return CredentialsItem{}, err
	}
	return s.GetForURL(url)
}

// GetForKey implements DataStore interface. Uses service default store.
func (k *keyringService) GetForKey(key string) (KeyValueItem, error) {
	s, err := k.defaultStore()
	if err != nil {
		return KeyValueItem{}, err
	}
	return s.GetForKey(key)
}

// AddItem implements DataStore interface. Uses service default store.
func (k *keyringService) AddItem(item StorageItem) error {
	s, err := k.defaultStore()
	if err != nil {
		return err
	}
	return s.AddItem(item)
}

// RemoveByURL implements DataStore interface. Uses service default store.
func (k *keyringService) RemoveByURL(url string) error {
	s, err := k.defaultStore()
	if err != nil {
		return err
	}
	return s.RemoveByURL(url)
}

// RemoveByKey implements DataStore interface. Uses service default store.
func (k *keyringService) RemoveByKey(key string) error {
	s, err := k.defaultStore()
	if err != nil {
		return err
	}
	return s.RemoveByKey(key)
}

// RemoveByKey implements DataStore interface. Uses service default store.
func (k *keyringService) cleanStorage(item StorageItem) error {
	s, err := k.defaultStore()
	if err != nil {
		return err
	}
	return s.cleanStorage(item)
}

// Save implements DataStore interface. Uses service default store.
func (k *keyringService) Save() error {
	s, err := k.defaultStore()
	if err != nil {
		return err
	}
	return s.Save()
}

// Destroy implements DataStore interface. Uses service default store.
func (k *keyringService) Destroy() error {
	s, err := k.defaultStore()
	if err != nil {
		return err
	}
	return s.Destroy()
}

type dataStoreYaml struct {
	file   CredentialsFile
	data   Storage
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
	var storage Storage
	err = dec.Decode(&storage)
	if err != nil {
		if strings.Contains(err.Error(), ErrKeyringMalformed.Error()) {
			// The keyring is malformed, treat it as new.
			s.file.Lock()
			s.loaded = true
			return nil
		}
		return err
	}
	s.data = storage
	s.loaded = true
	return nil
}

// GetForURL implements DataStore interface.
func (s *dataStoreYaml) GetForURL(url string) (CredentialsItem, error) {
	if err := s.load(); err != nil {
		return CredentialsItem{}, err
	}
	for i := 0; i < len(s.data.CredentialItems); i++ {
		if s.data.CredentialItems[i].URL == url {
			return s.data.CredentialItems[i], nil
		}
	}
	return CredentialsItem{}, ErrNotFound
}

func (s *dataStoreYaml) GetForKey(key string) (KeyValueItem, error) {
	if err := s.load(); err != nil {
		return KeyValueItem{}, err
	}
	for i := 0; i < len(s.data.KeyValueItems); i++ {
		if s.data.KeyValueItems[i].Key == key {
			return s.data.KeyValueItems[i], nil
		}
	}

	return KeyValueItem{}, ErrNotFound
}

// AddItem implements DataStore interface.
func (s *dataStoreYaml) AddItem(item StorageItem) error {
	if item.isEmpty() {
		return ErrEmptyFields
	}

	if err := s.load(); err != nil {
		return err
	}

	switch dataItem := item.(type) {
	case CredentialsItem:
		urlIdx := -1
		for i := 0; i < len(s.data.CredentialItems); i++ {
			if s.data.CredentialItems[i].URL == dataItem.URL {
				urlIdx = i
				break
			}
		}
		if urlIdx != -1 {
			s.data.CredentialItems[urlIdx] = dataItem
		} else {
			s.data.CredentialItems = append(s.data.CredentialItems, dataItem)
		}
	case KeyValueItem:
		urlIdx := -1
		for i := 0; i < len(s.data.KeyValueItems); i++ {
			if s.data.KeyValueItems[i].Key == dataItem.Key {
				urlIdx = i
				break
			}
		}
		if urlIdx != -1 {
			s.data.KeyValueItems[urlIdx] = dataItem
		} else {
			s.data.KeyValueItems = append(s.data.KeyValueItems, dataItem)
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
	for i := 0; i < len(s.data.CredentialItems); i++ {
		if s.data.CredentialItems[i].URL == url {
			s.data.CredentialItems = append(s.data.CredentialItems[:i], s.data.CredentialItems[i+1:]...)
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
	for i := 0; i < len(s.data.CredentialItems); i++ {
		if s.data.KeyValueItems[i].Key == key {
			s.data.KeyValueItems = append(s.data.KeyValueItems[:i], s.data.KeyValueItems[i+1:]...)
			return nil
		}
	}
	return ErrNotFound
}

// cleanStorage implements DataStore interface.
func (s *dataStoreYaml) cleanStorage(item StorageItem) error {
	if err := s.load(); err != nil {
		return err
	}

	switch item.(type) {
	case CredentialsItem:
		s.data.CredentialItems = []CredentialsItem{}
	case KeyValueItem:
		s.data.KeyValueItems = []KeyValueItem{}
	default:
		panic(errors.New("unknown storage type"))
	}

	return nil
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
