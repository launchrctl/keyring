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
	ErrNotFound         = errors.New("credential item not found")  // ErrNotFound if an item was not found
	ErrEmptyFields      = errors.New("credentials can't be empty") // ErrEmptyFields if fields are empty
	ErrEmptyPass        = errors.New("passphrase can't be empty")  // ErrEmptyPass if a passphrase is empty
	ErrKeyringMalformed = errors.New("the keyring is malformed")   // ErrKeyringMalformed when keyring can't be read.
)

// CredentialsItem stores credentials.
type CredentialsItem struct {
	URL      string `yaml:"url"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// CredentialsStore provides password storage functionality.
type CredentialsStore interface {
	// GetForURL returns a credentials item by a URL.
	// Error is returned if either the keyring could not be unlocked
	// Error ErrNotFound if the credentials were not found.
	GetForURL(url string) (CredentialsItem, error)
	// AddItem adds a new credential item.
	// Error is returned if the vault couldn't be unlocked.
	// Error ErrEmptyFields is returned if item is empty.
	AddItem(CredentialsItem) error
	// RemoveItem deletes an item by url.
	// Error is returned if the vault couldn't be unlocked.
	// Error ErrNotFound if the credentials were not found.
	RemoveItem(url string) error
	// Save saves the keyring to the persistent storage.
	Save() error
	// Destroy removes the keyring from the persistent storage.
	Destroy() error
}

// Keyring is a launchr.Service providing password store functionality.
type Keyring interface {
	launchr.Service
	CredentialsStore
}

type keyringService struct {
	fname string
	store CredentialsStore
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

func (k *keyringService) defaultStore() (CredentialsStore, error) {
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
	k.store = &credentialsStoreYaml{file: newAgeFile(k.fname, askPass)}
	return k.store, nil
}

// GetForURL implements CredentialsStore interface. Uses service default store.
func (k *keyringService) GetForURL(url string) (CredentialsItem, error) {
	s, err := k.defaultStore()
	if err != nil {
		return CredentialsItem{}, err
	}
	return s.GetForURL(url)
}

// AddItem implements CredentialsStore interface. Uses service default store.
func (k *keyringService) AddItem(item CredentialsItem) error {
	s, err := k.defaultStore()
	if err != nil {
		return err
	}
	return s.AddItem(item)
}

// RemoveItem implements CredentialsStore interface. Uses service default store.
func (k *keyringService) RemoveItem(url string) error {
	s, err := k.defaultStore()
	if err != nil {
		return err
	}
	return s.RemoveItem(url)
}

// Save implements CredentialsStore interface. Uses service default store.
func (k *keyringService) Save() error {
	s, err := k.defaultStore()
	if err != nil {
		return err
	}
	return s.Save()
}

// Destroy implements CredentialsStore interface. Uses service default store.
func (k *keyringService) Destroy() error {
	s, err := k.defaultStore()
	if err != nil {
		return err
	}
	return s.Destroy()
}

type credentialsStoreYaml struct {
	file   CredentialsFile
	items  []CredentialsItem
	loaded bool
}

func (s *credentialsStoreYaml) load() error {
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
	var items []CredentialsItem
	err = dec.Decode(&items)
	if err != nil {
		if strings.Contains(err.Error(), ErrKeyringMalformed.Error()) {
			// The keyring is malformed, treat it as new.
			s.file.Lock()
			s.loaded = true
			return nil
		}
		return err
	}
	s.items = items
	s.loaded = true
	return nil
}

// GetForURL implements CredentialsStore interface.
func (s *credentialsStoreYaml) GetForURL(url string) (CredentialsItem, error) {
	if err := s.load(); err != nil {
		return CredentialsItem{}, err
	}
	for i := 0; i < len(s.items); i++ {
		if s.items[i].URL == url {
			return s.items[i], nil
		}
	}
	return CredentialsItem{}, ErrNotFound
}

// AddItem implements CredentialsStore interface.
func (s *credentialsStoreYaml) AddItem(item CredentialsItem) error {
	if item.URL == "" || item.Username == "" || item.Password == "" {
		return ErrEmptyFields
	}
	if err := s.load(); err != nil {
		return err
	}
	// Check if it already an item and upsert it
	urlIdx := -1
	for i := 0; i < len(s.items); i++ {
		if s.items[i].URL == item.URL {
			urlIdx = i
			break
		}
	}
	if urlIdx != -1 {
		s.items[urlIdx] = item
	} else {
		s.items = append(s.items, item)
	}
	return nil
}

// RemoveItem implements CredentialsStore interface.
func (s *credentialsStoreYaml) RemoveItem(url string) error {
	if err := s.load(); err != nil {
		return err
	}
	for i := 0; i < len(s.items); i++ {
		if s.items[i].URL == url {
			s.items = append(s.items[:i], s.items[i+1:]...)
			return nil
		}
	}
	return ErrNotFound
}

// Save implements CredentialsStore interface.
func (s *credentialsStoreYaml) Save() error {
	err := s.file.Open(os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer s.file.Close()
	if err = s.file.Unlock(true); err != nil {
		return err
	}
	enc := yaml.NewEncoder(s.file)
	return enc.Encode(s.items)
}

// Destroy implements CredentialsStore interface.
func (s *credentialsStoreYaml) Destroy() error {
	return s.file.Remove()
}
