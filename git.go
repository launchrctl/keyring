package keyring

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/launchrctl/launchr"
)

// GitCredentialOp represents a git credential helper operation.
type GitCredentialOp string

const (
	GitCredentialGet   GitCredentialOp = "get"
	GitCredentialStore GitCredentialOp = "store"
	GitCredentialErase GitCredentialOp = "erase"
)

// GitCredential represents a git credential request/response.
type GitCredential struct {
	Protocol string
	Host     string
	Path     string
	Username string
	Password string
}

// ParseGitCredential parses git credential helper input from stdin.
func ParseGitCredential(r io.Reader) (*GitCredential, error) {
	cred := &GitCredential{}
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break // Empty line terminates input
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key, value := parts[0], parts[1]
		switch key {
		case "protocol":
			cred.Protocol = value
		case "host":
			cred.Host = value
		case "path":
			cred.Path = value
		case "username":
			cred.Username = value
		case "password":
			cred.Password = value
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return cred, nil
}

// ToURL constructs a URL from the credential fields.
func (c *GitCredential) ToURL() string {
	u := &url.URL{
		Scheme: c.Protocol,
		Host:   c.Host,
	}
	if c.Path != "" {
		u.Path = "/" + c.Path
	}
	return u.String()
}

// BaseURL returns the base URL (protocol://host) without path.
func (c *GitCredential) BaseURL() string {
	return fmt.Sprintf("%s://%s", c.Protocol, c.Host)
}

// Write outputs the credential in git credential helper format.
func (c *GitCredential) Write(w io.Writer) error {
	if c.Protocol != "" {
		fmt.Fprintf(w, "protocol=%s\n", c.Protocol)
	}
	if c.Host != "" {
		fmt.Fprintf(w, "host=%s\n", c.Host)
	}
	if c.Username != "" {
		fmt.Fprintf(w, "username=%s\n", c.Username)
	}
	if c.Password != "" {
		fmt.Fprintf(w, "password=%s\n", c.Password)
	}
	fmt.Fprintln(w) // Empty line to terminate
	return nil
}

// HandleGitCredential handles git credential helper operations.
func HandleGitCredential(k Keyring, op GitCredentialOp, in io.Reader, out io.Writer) error {
	switch op {
	case GitCredentialGet:
		return handleGitCredentialGet(k, in, out)
	case GitCredentialStore:
		return handleGitCredentialStore(k, in)
	case GitCredentialErase:
		return handleGitCredentialErase(k, in)
	default:
		return fmt.Errorf("unknown git credential operation: %s", op)
	}
}

func handleGitCredentialGet(k Keyring, in io.Reader, out io.Writer) error {
	cred, err := ParseGitCredential(in)
	if err != nil {
		return err
	}

	// Try to find credentials for this URL
	baseURL := cred.BaseURL()
	storedCreds, err := k.GetForURL(baseURL)
	if err != nil {
		// Try with https:// prefix if not found
		if !strings.HasPrefix(baseURL, "https://") {
			baseURL = "https://" + cred.Host
			storedCreds, err = k.GetForURL(baseURL)
		}
		if err != nil {
			return nil // No credentials found, git will try other methods
		}
	}

	// Check if OAuth token needs refresh
	if storedCreds.IsOAuth() && storedCreds.IsExpired() {
		refreshed, changed, refreshErr := RefreshCredentials(context.Background(), storedCreds)
		if refreshErr != nil {
			launchr.Log().Warn("token refresh failed", "error", refreshErr)
			// Continue with expired token, it might still work
		} else if changed {
			storedCreds = *refreshed
			// Save the refreshed credentials
			if err := k.AddItem(storedCreds); err == nil {
				_ = k.Save()
			}
		}
	}

	// Return credentials to git
	response := &GitCredential{
		Protocol: cred.Protocol,
		Host:     cred.Host,
		Username: storedCreds.Username,
		Password: storedCreds.GetSecret(),
	}

	return response.Write(out)
}

func handleGitCredentialStore(k Keyring, in io.Reader) error {
	cred, err := ParseGitCredential(in)
	if err != nil {
		return err
	}

	// Don't overwrite OAuth credentials with basic auth from git
	baseURL := cred.BaseURL()
	existing, err := k.GetForURL(baseURL)
	if err == nil && existing.IsOAuth() {
		// Don't overwrite OAuth credentials
		return nil
	}

	// Store as basic auth credentials
	item := CredentialsItem{
		URL:      baseURL,
		Username: cred.Username,
		Password: cred.Password,
		AuthType: AuthTypeBasic,
	}

	if err := k.AddItem(item); err != nil {
		return err
	}

	return k.Save()
}

func handleGitCredentialErase(k Keyring, in io.Reader) error {
	cred, err := ParseGitCredential(in)
	if err != nil {
		return err
	}

	baseURL := cred.BaseURL()
	if err := k.RemoveByURL(baseURL); err != nil {
		return nil // Ignore not found errors
	}

	return k.Save()
}

// SetupGitCredentialHelper configures git to use plasmactl as credential helper.
func SetupGitCredentialHelper(global bool, urlPattern string, printer *launchr.Terminal) error {
	// Get the path to the current executable
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// Build the credential helper command
	// Git will call: plasmactl keyring:git --credential get
	helperCmd := fmt.Sprintf("!%s keyring:git --credential", execPath)

	// Build git config command
	args := []string{"config"}
	if global {
		args = append(args, "--global")
	}

	if urlPattern != "" {
		// URL-specific credential helper
		// git config credential.https://example.com.helper "!plasmactl keyring:git --credential"
		args = append(args, fmt.Sprintf("credential.%s.helper", urlPattern), helperCmd)
	} else {
		// Global credential helper
		args = append(args, "credential.helper", helperCmd)
	}

	cmd := exec.Command("git", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to configure git: %w", err)
	}

	if urlPattern != "" {
		printer.Success().Printfln("Git credential helper configured for %s", urlPattern)
	} else if global {
		printer.Success().Println("Git credential helper configured globally")
	} else {
		printer.Success().Println("Git credential helper configured for this repository")
	}

	return nil
}
