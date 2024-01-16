// Package keyring provides password store functionality.
package keyring

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/launchrctl/launchr"
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
	return nil
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
	var fLogoutAll bool
	var logoutCmd = &cobra.Command{
		Use:   "logout [URL]",
		Short: "Logs out from a service",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if fLogoutAll && len(args) > 0 || !fLogoutAll && len(args) == 0 {
				return fmt.Errorf("please, either provide a url or use --all flag")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// Don't show usage help on a runtime error.
			cmd.SilenceUsage = true
			if fLogoutAll {
				return logoutAll(p.k)
			}
			return logout(p.k, args[0])
		},
	}

	// Credentials flags
	loginCmd.Flags().StringVarP(&creds.URL, "url", "", "", "URL")
	loginCmd.Flags().StringVarP(&creds.Username, "username", "", "", "Username")
	loginCmd.Flags().StringVarP(&creds.Password, "password", "", "", "Password")
	// Logout flags
	logoutCmd.Flags().BoolVarP(&fLogoutAll, "all", "", false, "Logs out from all services")
	// Passphrase flags
	rootCmd.PersistentFlags().StringVarP(&passphrase, "keyring-passphrase", "", "", "Passphrase for keyring encryption/decryption")
	// Command flags.
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(logoutCmd)
	return nil
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

func logout(k Keyring, url string) error {
	err := k.RemoveItem(url)
	if err != nil {
		return err
	}
	return k.Save()
}

func logoutAll(k Keyring) error {
	return k.Destroy()
}
