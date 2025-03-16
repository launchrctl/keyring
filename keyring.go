package keyring

import (
	"errors"

	"github.com/launchrctl/launchr"
)

const defaultFileYaml = "keyring.yaml"

// Keyring errors.
var (
	ErrNotFound         = errors.New("item not found")            // ErrNotFound if an item was not found
	ErrEmptyFields      = errors.New("item can't be empty")       // ErrEmptyFields if fields are empty
	ErrEmptyPass        = errors.New("passphrase can't be empty") // ErrEmptyPass if a passphrase is empty
	ErrKeyringMalformed = errors.New("the keyring is malformed")  // ErrKeyringMalformed when keyring can't be read.
)

// SecretItem is an interface that represents an item saved in a storage.
// It is used in the DataStore interface for adding and manipulating items.
type SecretItem interface {
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
	AddItem(SecretItem) error
	// RemoveByURL deletes an item by url.
	// Error is returned if the vault couldn't be unlocked.
	// Error ErrNotFound if the credentials were not found.
	RemoveByURL(url string) error
	// RemoveByKey deletes an item by key.
	// Error is returned if the vault couldn't be unlocked.
	// Error ErrNotFound if the credentials were not found.
	RemoveByKey(key string) error
	// CleanStorage cleanups storage (credentials or key-value).
	// Error is returned if the vault couldn't be unlocked.
	CleanStorage(item SecretItem) error
	// Exists checks if keyring exists in persistent storage.
	Exists() bool
	// Save saves the keyring to the persistent storage.
	Save() error
	// Destroy removes the keyring from the persistent storage.
	Destroy() error
}

// Keyring is a [launchr.Service] providing password store functionality.
type Keyring interface {
	launchr.Service
	DataStore
	ResetStorage()
}

type keyringService struct {
	fname string
	store DataStore
	cfg   launchr.Config
	mask  *launchr.SensitiveMask
}

func newKeyringService(cfg launchr.Config, mask *launchr.SensitiveMask) Keyring {
	return &keyringService{
		fname: cfg.Path(defaultFileYaml),
		cfg:   cfg,
		mask:  mask,
	}
}

// ServiceInfo implements [launchr.Service] interface.
func (k *keyringService) ServiceInfo() launchr.ServiceInfo {
	return launchr.ServiceInfo{}
}

// ResetStorage cleans store for subsequent reload.
func (k *keyringService) ResetStorage() {
	k.store = nil
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
	item, err := s.GetForURL(url)
	if err == nil {
		k.mask.AddString(item.Password)
	}
	return item, err
}

// GetForKey implements DataStore interface. Uses service default store.
func (k *keyringService) GetForKey(key string) (KeyValueItem, error) {
	s, err := k.defaultStore()
	if err != nil {
		return KeyValueItem{}, err
	}
	item, err := s.GetForKey(key)
	if err == nil {
		k.mask.AddString(item.Value)
	}
	return item, err
}

// AddItem implements DataStore interface. Uses service default store.
func (k *keyringService) AddItem(item SecretItem) error {
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

// CleanStorage implements DataStore interface. Uses service default store.
func (k *keyringService) CleanStorage(item SecretItem) error {
	s, err := k.defaultStore()
	if err != nil {
		return err
	}
	return s.CleanStorage(item)
}

// Exists implements DataStore, checks if keyring exists in persistent storage.
func (k *keyringService) Exists() bool {
	s, err := k.defaultStore()
	if err != nil {
		return false
	}
	return s.Exists()
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
