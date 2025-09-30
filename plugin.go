// Package keyring provides password store functionality.
package keyring

import (
	"bufio"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/launchrctl/launchr"
	"github.com/launchrctl/launchr/pkg/action"
	"github.com/launchrctl/launchr/pkg/jsonschema"
)

const (
	procGetKeyValue   = "keyring.GetKeyValue"
	errTplNotFoundURL = "%s not found in keyring. Use `%s keyring:login` to add it."
	errTplNotFoundKey = "%s not found in keyring. Use `%s keyring:set` to add it."

	envVarPassphrase     = launchr.EnvVar("keyring_passphrase")
	envVarPassphraseFile = launchr.EnvVar("keyring_passphrase_file")
)

var (
	passphrase     string
	passphraseFile string
)

var (
	//go:embed action.list.yaml
	actionListYaml []byte
	//go:embed action.login.yaml
	actionLoginYaml []byte
	//go:embed action.logout.yaml
	actionLogoutYaml []byte
	//go:embed action.set.yaml
	actionSetYaml []byte
	//go:embed action.unset.yaml
	actionUnsetYaml []byte
	//go:embed action.purge.yaml
	actionPurgeYaml []byte
)

func init() {
	launchr.RegisterPlugin(&Plugin{})
}

// Plugin is [launchr.Plugin] plugin providing a keyring.
type Plugin struct {
	k    Keyring
	cfg  launchr.Config
	mask *launchr.SensitiveMask
}

// PluginInfo implements [launchr.Plugin] interface.
func (p *Plugin) PluginInfo() launchr.PluginInfo {
	return launchr.PluginInfo{}
}

// OnAppInit implements [launchr.Plugin] interface.
func (p *Plugin) OnAppInit(app launchr.App) error {
	p.mask = app.SensitiveMask()
	app.GetService(&p.cfg)
	p.k = newKeyringService(p.cfg, p.mask)
	app.AddService(p.k)

	var m action.Manager
	app.GetService(&m)

	addValueProcessors(m, p.k)
	return nil
}

// GetKeyValueProcessorOptions is a [action.ValueProcessorOptions] struct.
type GetKeyValueProcessorOptions = *action.GenericValueProcessorOptions[struct {
	Key string `yaml:"key" validate:"not-empty"`
}]

// addValueProcessors adds a keyring [action.ValueProcessor] to [action.Manager].
func addValueProcessors(m action.Manager, keyring Keyring) {
	m.AddValueProcessor(procGetKeyValue, action.GenericValueProcessor[GetKeyValueProcessorOptions]{
		Types: []jsonschema.Type{jsonschema.String},
		Fn: func(v any, opts GetKeyValueProcessorOptions, ctx action.ValueProcessorContext) (any, error) {
			return processGetByKey(v, opts, ctx, keyring)
		},
	})
}

func processGetByKey(value any, opts GetKeyValueProcessorOptions, ctx action.ValueProcessorContext, k Keyring) (any, error) {
	if ctx.IsChanged {
		launchr.Term().Warning().Printfln("Skipping processor %q, value is not empty. Value will remain unchanged", procGetKeyValue)
		launchr.Log().Warn("skipping processor, value is not empty", "processor", procGetKeyValue)
		return value, nil
	}

	v, err := k.GetForKey(opts.Fields.Key)
	if err == nil {
		return v.Value, nil
	}

	streams := ctx.Input.Streams()
	isTerminal := streams != nil && streams.In().IsTerminal()
	if errors.Is(err, ErrNotFound) && isTerminal {
		item := KeyValueItem{Key: opts.Fields.Key}
		err = RequestKeyValueFromTty(&item)
		if err != nil {
			return value, err
		}

		err = k.AddItem(item)
		if err != nil {
			return value, err
		}

		// Ensure keyring storage will be accessible after save.
		defer k.ResetStorage()
		err = k.Save()
		if err != nil {
			return value, err
		}
		launchr.Term().Info().Printfln("Key %q has been added to keyring", item.Key)

		return item.Value, nil
	}

	return value, buildNotFoundError(opts.Fields.Key, errTplNotFoundKey, err)
}

// DiscoverActions implements [launchr.ActionDiscoveryPlugin] interface.
func (p *Plugin) DiscoverActions(_ context.Context) ([]*action.Action, error) {
	// Action list.
	listCmd := action.NewFromYAML("keyring:list", actionListYaml)
	listCmd.SetRuntime(action.NewFnRuntime(func(_ context.Context, a *action.Action) error {
		printer := launchr.Term()
		if rt, ok := a.Runtime().(action.RuntimeTermAware); ok {
			printer = rt.Term()
		}

		return list(p.k, printer)
	}))

	// Action login.
	loginCmd := action.NewFromYAML("keyring:login", actionLoginYaml)
	loginCmd.SetRuntime(action.NewFnRuntime(func(_ context.Context, a *action.Action) error {
		input := a.Input()
		creds := CredentialsItem{
			Username: input.Opt("username").(string),
			Password: input.Opt("password").(string),
			URL:      input.Opt("url").(string),
		}
		return login(p.k, creds)
	}))

	// Action logout.
	logoutCmd := action.NewFromYAML("keyring:logout", actionLogoutYaml)
	logoutCmd.SetRuntime(action.NewFnRuntime(func(_ context.Context, a *action.Action) error {
		input := a.Input()
		all := input.Opt("all").(bool)
		if all == input.IsArgChanged("url") {
			return fmt.Errorf("please, either provide an URL or use --all flag")
		}
		url, _ := input.Arg("url").(string)
		return logout(p.k, url, all)
	}))

	// Action set.
	setKeyCmd := action.NewFromYAML("keyring:set", actionSetYaml)
	setKeyCmd.SetRuntime(action.NewFnRuntime(func(_ context.Context, a *action.Action) error {
		input := a.Input()
		key := KeyValueItem{
			Key: input.Arg("key").(string),
		}

		userValue := input.Arg("value").(string)
		format := input.Opt("format").(string)
		var err error

		// @TODO cover with tests
		key.Value, err = parseFromString(format, userValue)
		if err != nil {
			return fmt.Errorf("failed to parse %s: %w", format, err)
		}

		return saveKey(p.k, key)
	}))

	// Action unset.
	unsetKeyCmd := action.NewFromYAML("keyring:unset", actionUnsetYaml)
	unsetKeyCmd.SetRuntime(action.NewFnRuntime(func(_ context.Context, a *action.Action) error {
		input := a.Input()
		all := input.Opt("all").(bool)
		if all == input.IsArgChanged("key") {
			return fmt.Errorf("please, either target key or use --all flag")
		}
		key, _ := input.Arg("key").(string)
		return removeKey(p.k, key, all)
	}))

	// Action purge.
	purgeCmd := action.NewFromYAML("keyring:purge", actionPurgeYaml)
	purgeCmd.SetRuntime(action.NewFnRuntime(func(_ context.Context, _ *action.Action) error {
		return purge(p.k)
	}))

	return []*action.Action{
		listCmd,
		loginCmd,
		logoutCmd,
		setKeyCmd,
		unsetKeyCmd,
		purgeCmd,
	}, nil
}

// CobraAddCommands implements [launchr.CobraPlugin] interface to provide keyring functionality.
func (p *Plugin) CobraAddCommands(rootCmd *launchr.Command) error {
	rootCmd.PersistentFlags().StringVarP(&passphrase, "keyring-passphrase", "", "", "Passphrase for keyring encryption/decryption")
	rootCmd.PersistentFlags().StringVarP(&passphraseFile, "keyring-passphrase-file", "", "", "File containing passphrase for keyring encryption/decryption")
	return nil
}

// PersistentPreRun implements [launchr.PersistentPreRun] interface.
func (p *Plugin) PersistentPreRun(_ *launchr.Command, _ []string) error {
	setPassphrase()
	// If the passphrase is set with env variables, hide them.
	if passphraseFile == "" && passphrase != "" {
		p.mask.AddString(passphrase)
	}
	if passphraseFile != "" {
		p.mask.AddString(passphraseFile)
	}
	return nil
}

func buildNotFoundError(item, template string, err error) error {
	if !errors.Is(err, ErrNotFound) {
		return err
	}

	version := launchr.Version()
	return fmt.Errorf(template, item, version.Name)
}

func list(k Keyring, printer *launchr.Terminal) error {
	urls, err := k.GetUrls()
	if err != nil {
		return err
	}

	keys, err := k.GetKeys()
	if err != nil {
		return err
	}

	// Show both key-value pairs and URLs
	if len(keys) > 0 {
		printer.Info().Printfln("Key-value pairs:")
		for _, key := range keys {
			printer.Printfln("- %s", key)
		}
	}

	if len(urls) > 0 {
		printer.Info().Printfln("URLs:")
		for _, url := range urls {
			printer.Printfln("- %s", url)
		}
	}

	if len(urls) == 0 && len(keys) == 0 {
		printer.Info().Printfln("No items found in keyring")
	}

	return nil
}

func login(k Keyring, creds CredentialsItem) error {
	// Ask for login elements if some elements are empty.
	if creds.isEmpty() {
		err := RequestCredentialsFromTty(&creds)
		if err != nil {
			return err
		}
	}

	err := k.AddItem(creds)
	if err != nil {
		return err
	}
	return k.Save()
}

func saveKey(k Keyring, item KeyValueItem) error {
	// Ask for login elements if some elements are empty.
	if item.isEmpty() {
		err := RequestKeyValueFromTty(&item)
		if err != nil {
			return err
		}
	}

	err := k.AddItem(item)
	if err != nil {
		return err
	}
	return k.Save()
}

// RequestCredentialsFromTty gets credentials from tty.
func RequestCredentialsFromTty(creds *CredentialsItem) error {
	return withTerminal(func(in, out *os.File) error {
		return credentialsFromTty(creds, in, out)
	})
}

func credentialsFromTty(creds *CredentialsItem, in *os.File, out *os.File) error {
	reader := bufio.NewReader(in)

	if creds.URL == "" {
		fmt.Fprint(out, "URL: ")
		url, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		creds.URL = strings.TrimSpace(url)
	}

	if creds.Username == "" {
		fmt.Fprint(out, "Username: ")
		username, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		creds.Username = strings.TrimSpace(username)
	}

	if creds.Password == "" {
		fmt.Fprint(out, "Password: ")
		bytePassword, err := term.ReadPassword(int(in.Fd()))
		fmt.Fprint(out, "\n")
		if err != nil {
			return err
		}
		creds.Password = strings.TrimSpace(string(bytePassword))
	}
	return nil
}

// RequestKeyValueFromTty gets key-value pair from tty.
func RequestKeyValueFromTty(item *KeyValueItem) error {
	return withTerminal(func(in, out *os.File) error {
		return keyValueFromTty(item, in, out)
	})
}

func keyValueFromTty(item *KeyValueItem, in *os.File, out *os.File) error {
	reader := bufio.NewReader(in)

	showKeyHelp := true
	if item.Key == "" {
		showKeyHelp = false
		fmt.Fprint(out, "Key: ")
		username, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		item.Key = strings.TrimSpace(username)
	}

	if item.Value == "" {
		if showKeyHelp {
			fmt.Fprintf(out, "Enter value of '%s':", item.Key)
		} else {
			fmt.Fprint(out, "Value: ")
		}

		byteValue, err := term.ReadPassword(int(in.Fd()))
		fmt.Fprint(out, "\n")
		if err != nil {
			return err
		}
		item.Value = strings.TrimSpace(string(byteValue))
	}
	return nil
}

func logout(k Keyring, url string, all bool) error {
	var err error
	if all {
		err = k.CleanStorage(CredentialsItem{})
	} else {
		err = k.RemoveByURL(url)
	}
	if err != nil {
		return buildNotFoundError(url, errTplNotFoundURL, err)
	}

	return k.Save()
}

func removeKey(k Keyring, key string, all bool) error {
	var err error
	if all {
		err = k.CleanStorage(KeyValueItem{})
	} else {
		err = k.RemoveByKey(key)
	}
	if err != nil {
		return buildNotFoundError(key, errTplNotFoundKey, err)
	}

	return k.Save()
}

func purge(k Keyring) error {
	return k.Destroy()
}

func setPassphrase() {
	// Return passphrase if it's already provided.
	if passphrase != "" {
		return
	}
	// Check env variable for the passphrase.
	passphrase = envVarPassphrase.Get()
	if passphrase != "" {
		return
	}
	if envPassFile := envVarPassphraseFile.Get(); passphraseFile == "" && envPassFile != "" {
		passphraseFile = launchr.MustAbs(envPassFile)
		// Override to absolute path.
		_ = envVarPassphraseFile.Set(passphraseFile)
	}

	// Try to read a secret from a file.
	if passphraseFile != "" {
		passphraseFile = launchr.MustAbs(passphraseFile)
		bytes, err := os.ReadFile(passphraseFile) //nolint:gosec // Filepath checked on previous line.
		if err != nil {
			return
		}
		passphrase = strings.TrimSpace(string(bytes))
		// Set env variable for subprocesses.
		_ = envVarPassphraseFile.Set(passphraseFile)
		return
	}
}
