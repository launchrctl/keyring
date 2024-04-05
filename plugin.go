// Package keyring provides password store functionality.
package keyring

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/launchrctl/launchr"
	"github.com/launchrctl/launchr/pkg/action"
	"github.com/launchrctl/launchr/pkg/jsonschema"
	"github.com/launchrctl/launchr/pkg/log"
)

const (
	getByKeyProc      = "keyring.GetKeyValue"
	errTplNotFoundURL = "%s not found in keyring. Use `%s login` to add it."
	errTplNotFoundKey = "%s not found in keyring. Use `%s set` to add it."
)

func init() {
	launchr.RegisterPlugin(&Plugin{})
}

// Plugin is launchr plugin providing keyring.
type Plugin struct {
	k   Keyring
	cfg launchr.Config
}

// PluginInfo implements launchr.Plugin interface.
func (p *Plugin) PluginInfo() launchr.PluginInfo {
	return launchr.PluginInfo{}
}

// OnAppInit implements launchr.Plugin interface.
func (p *Plugin) OnAppInit(app launchr.App) error {
	app.GetService(&p.cfg)
	p.k = newKeyringService(p.cfg)
	app.AddService(p.k)

	var m action.Manager
	app.GetService(&m)

	AddValueProcessors(m, p.k)
	return nil
}

// AddValueProcessors submits new ValueProcessors to action.Manager.
func AddValueProcessors(m action.Manager, keyring Keyring) {
	getByKey := func(value interface{}, options map[string]interface{}) (interface{}, error) {
		return getByKeyProcessor(value, options, keyring)
	}

	proc := action.NewFuncProcessor([]jsonschema.Type{jsonschema.String}, getByKey)
	m.AddValueProcessor(getByKeyProc, proc)
}

func getByKeyProcessor(value interface{}, options map[string]interface{}, k Keyring) (interface{}, error) {
	val, ok := value.(string)
	if !ok {
		return val, fmt.Errorf(
			"string type is expected for %q processor. Change value type or remove the processor", getByKeyProc,
		)
	}

	if val != "" {
		log.Debug("skipping %s processor, value is not empty. Value remains unchanged", getByKeyProc)
		return value, nil
	}

	key, ok := options["key"].(string)
	if !ok {
		return value, fmt.Errorf("option `key` is required for %q processor", getByKeyProc)
	}

	v, err := k.GetForKey(key)
	if err != nil {
		return value, buildNotFoundError(key, errTplNotFoundKey, err)
	}

	return v.Value, nil

}

var passphrase string

// CobraAddCommands implements launchr.CobraPlugin interface to provide keyring functionality.
func (p *Plugin) CobraAddCommands(rootCmd *cobra.Command) error {
	var creds CredentialsItem
	var loginCmd = &cobra.Command{
		Use:   "login",
		Short: "Logs in to services like git, docker, etc.",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Don't show usage help on a runtime error.
			cmd.SilenceUsage = true
			return login(p.k, creds)
		},
	}

	var cleanAll bool
	var logoutCmd = &cobra.Command{
		Use:   "logout [URL]",
		Short: "Logs out from a service",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return ensureCleanOption(cmd, args, "please, either provide an URL or use --all flag", cleanAll)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// Don't show usage help on a runtime error.
			cmd.SilenceUsage = true

			urlArg := ""
			if len(args) > 0 {
				urlArg = args[0]
			}

			return logout(p.k, urlArg, cleanAll)
		},
	}

	var key KeyValueItem
	var setKeyCmd = &cobra.Command{
		Use:   "set [key]",
		Short: "Store new key-value pair to keyring",
		Args:  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Don't show usage help on a runtime error.
			cmd.SilenceUsage = true

			key.Key = args[0]
			return saveKey(p.k, key)
		},
	}

	var unsetKeyCmd = &cobra.Command{
		Use:   "unset [key]",
		Short: "Removes key-value pair from keyring",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return ensureCleanOption(cmd, args, "please, either target key or use --all flag", cleanAll)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// Don't show usage help on a runtime error.
			cmd.SilenceUsage = true

			keyArg := ""
			if len(args) > 0 {
				keyArg = args[0]
			}

			return removeKey(p.k, keyArg, cleanAll)
		},
	}

	var purgeCmd = &cobra.Command{
		Use:   "purge",
		Short: "Remove existing keyring file",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Don't show usage help on a runtime error.
			cmd.SilenceUsage = true
			return purge(p.k)
		},
	}

	// Credentials flags
	loginCmd.Flags().StringVarP(&creds.URL, "url", "", "", "URL")
	loginCmd.Flags().StringVarP(&creds.Username, "username", "", "", "Username")
	loginCmd.Flags().StringVarP(&creds.Password, "password", "", "", "Password")
	// Logout flags
	logoutCmd.Flags().BoolVarP(&cleanAll, "all", "", false, "Logs out from all services")
	// Key flags
	setKeyCmd.Flags().StringVarP(&key.Value, "value", "", "", "Value")
	// Unset flags
	unsetKeyCmd.Flags().BoolVarP(&cleanAll, "all", "", false, "Removes all key-pairs")
	// Passphrase flags
	rootCmd.PersistentFlags().StringVarP(&passphrase, "keyring-passphrase", "", "", "Passphrase for keyring encryption/decryption")
	// Command flags.
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(logoutCmd)
	rootCmd.AddCommand(setKeyCmd)
	rootCmd.AddCommand(unsetKeyCmd)
	rootCmd.AddCommand(purgeCmd)
	return nil
}

func ensureCleanOption(_ *cobra.Command, args []string, message string, cleanAll bool) error {
	if cleanAll && len(args) > 0 || !cleanAll && len(args) == 0 {
		return fmt.Errorf(message)
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

func login(k Keyring, creds CredentialsItem) error {
	// Ask for login elements if some elements are empty.
	var err error
	if creds == (CredentialsItem{}) {
		err = RequestCredentialsFromTty(&creds)
		if err != nil {
			return err
		}
	}

	err = k.AddItem(creds)
	if err != nil {
		return err
	}
	return k.Save()
}

func saveKey(k Keyring, item KeyValueItem) error {
	// Ask for login elements if some elements are empty.
	err := RequestKeyValueFromTty(&item)
	if err != nil {
		return err
	}

	err = k.AddItem(item)
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

	if item.Key == "" {
		fmt.Fprint(out, "Key: ")
		username, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		item.Key = strings.TrimSpace(username)
	}

	if item.Value == "" {
		fmt.Fprint(out, "Value: ")
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
