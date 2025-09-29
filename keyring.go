package keyring

import (
	"errors"
	"reflect"

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
	Value any    `yaml:"value"`
}

func (i KeyValueItem) isEmpty() bool {
	if i.Key == "" {
		return true
	}

	if i.Value == nil {
		return true
	}

	// Use reflection to check if the value is its zero value
	v := reflect.ValueOf(i.Value)

	switch v.Kind() {
	case reflect.String: // also handles type alias for string.
		return v.String() == ""
	case reflect.Slice, reflect.Map, reflect.Array:
		return v.Len() == 0
	case reflect.Ptr, reflect.Interface, reflect.Chan, reflect.Func:
		return v.IsNil()
	default:
		// For other types, check if it's the zero value
		return v.IsZero()
	}
}

// DataStore provides password storage functionality.
type DataStore interface {
	// GetUrls retrieves a list of stored URLs.
	GetUrls() ([]string, error)
	// GetKeys retrieves a list of stored keys.
	GetKeys() ([]string, error)
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
type Keyring = *keyringService

type keyringService struct {
	store DataStore
	mask  *launchr.SensitiveMask
}

// NewService creates a new Keyring service.
func NewService(store DataStore, mask *launchr.SensitiveMask) Keyring {
	return &keyringService{
		store: store,
		mask:  mask,
	}
}

// NewFileStore creates a DataStore using a file.
func NewFileStore(f CredentialsFile) DataStore {
	if f == nil {
		f = nullFile{}
	}
	return &dataStoreYaml{file: f}
}

// ServiceInfo implements [launchr.Service] interface.
func (k *keyringService) ServiceInfo() launchr.ServiceInfo {
	return launchr.ServiceInfo{}
}

func (k *keyringService) ServiceCreate(svc *launchr.ServiceManager) launchr.Service {
	var cfg launchr.Config
	var mask *launchr.SensitiveMask
	svc.Get(&cfg)
	svc.Get(&mask)

	// Read keyring from a global config directory.
	// TODO: parse header to know if it's encrypted or not.
	// TODO: do not encrypt if the passphrase is not provided.
	store := NewFileStore(
		NewAgeFile(
			cfg.Path(defaultFileYaml),
			AskPassFirstAvailable{
				AskPassConst(passphrase.get),
				AskPassWithTerminal{},
			},
		),
	)

	return NewService(store, mask)
}

// ResetStorage cleans store for subsequent reload.
func (k *keyringService) ResetStorage() {
	k.store = nil
}

func (k *keyringService) defaultStore() (DataStore, error) {
	return k.store, nil
}

// GetUrls implements DataStore interface. Uses service default store.
func (k *keyringService) GetUrls() ([]string, error) {
	s, err := k.defaultStore()
	if err != nil {
		return []string{}, err
	}

	return s.GetUrls()
}

// GetKeys implements DataStore interface. Uses service default store.
func (k *keyringService) GetKeys() ([]string, error) {
	s, err := k.defaultStore()
	if err != nil {
		return []string{}, err
	}

	return s.GetKeys()
}

// GetForURL implements DataStore interface. Uses service default store.
func (k *keyringService) GetForURL(url string) (CredentialsItem, error) {
	s, err := k.defaultStore()
	if err != nil {
		return CredentialsItem{}, err
	}
	item, err := s.GetForURL(url)
	if err == nil {
		k.maskItem(item)
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
		k.maskItem(item)
	}
	return item, err
}

// AddItem implements DataStore interface. Uses service default store.
func (k *keyringService) AddItem(item SecretItem) error {
	s, err := k.defaultStore()
	if err != nil {
		return err
	}

	k.maskItem(item)
	return s.AddItem(item)
}

// MaskItem masks the item values
func (k *keyringService) maskItem(item SecretItem) {
	if k.mask == nil {
		return
	}
	switch dataItem := item.(type) {
	case CredentialsItem:
		k.mask.AddString(dataItem.Password)
	case KeyValueItem:
		if v, ok := dataItem.Value.(string); ok {
			k.mask.AddString(v)
		}
	default:
	}
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
