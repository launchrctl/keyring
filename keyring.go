package keyring

import (
	"errors"
	"reflect"

	"github.com/launchrctl/launchr"
)

const defaultFileYaml = "keyring.yaml"

// Keyring errors.
var (
	ErrNotFound         = errors.New("item not found")                    // ErrNotFound if an item was not found
	ErrEmptyFields      = errors.New("item can't be empty")               // ErrEmptyFields if fields are empty
	ErrEmptyPass        = errors.New("passphrase can't be empty")         // ErrEmptyPass if a passphrase is empty
	ErrKeyringMalformed = errors.New("the keyring is malformed")          // ErrKeyringMalformed when keyring can't be read.
	ErrIncorrectPass    = errors.New("the given passphrase is incorrect") // ErrIncorrectPass if a passphrase is incorrect
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

// dataStore is a type alias to embed it as a private property.
type dataStore = DataStore

// Keyring is a [launchr.Service] providing password store functionality.
type Keyring = *keyringService

type keyringService struct {
	dataStore
	mask *launchr.SensitiveMask
}

// NewService creates a new Keyring service.
func NewService(store DataStore, mask *launchr.SensitiveMask) Keyring {
	return &keyringService{
		dataStore: store,
		mask:      mask,
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
			cfg.Path(defaultFileYaml+".age"),
			AskPassFirstAvailable{
				AskPassConst(passphrase.get),
				AskPassWithTerminal{},
			},
		),
	)

	return NewService(store, mask)
}

// GetForURL implements DataStore interface. Uses service default store.
func (k *keyringService) GetForURL(url string) (CredentialsItem, error) {
	item, err := k.dataStore.GetForURL(url)
	if err == nil {
		k.maskItem(item)
	}
	return item, err
}

// GetForKey implements DataStore interface. Uses service default store.
func (k *keyringService) GetForKey(key string) (KeyValueItem, error) {
	item, err := k.dataStore.GetForKey(key)
	if err == nil {
		k.maskItem(item)
	}
	return item, err
}

// AddItem implements DataStore interface. Uses service default store.
func (k *keyringService) AddItem(item SecretItem) error {
	k.maskItem(item)
	return k.dataStore.AddItem(item)
}

// MaskItem masks the item values
func (k *keyringService) maskItem(item SecretItem) {
	if k.mask == nil {
		// Mask may be nil in unit tests for simplicity.
		// Mask is checked in e2e tests.
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
