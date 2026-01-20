package keyring

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/launchrctl/launchr"
	"golang.org/x/oauth2"
)

// Auth type constants.
const (
	AuthTypeBasic = "basic"
	AuthTypeOAuth = "oauth"
)

// OIDCConfig holds the discovered OIDC configuration.
type OIDCConfig struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	DeviceEndpoint        string `json:"device_authorization_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JwksURI               string `json:"jwks_uri"`
}

// DiscoverOIDC attempts to discover OIDC configuration from the given URL.
// Returns nil if no OIDC configuration is found (not an error - just means no OAuth).
func DiscoverOIDC(ctx context.Context, baseURL string) (*OIDCConfig, error) {
	// Normalize URL
	baseURL = strings.TrimSuffix(baseURL, "/")

	// Try well-known endpoint
	wellKnownURL := baseURL + "/.well-known/openid-configuration"

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnownURL, nil)
	if err != nil {
		return nil, nil // Not an error, just no OIDC
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil // Network error, assume no OIDC
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil // No OIDC available
	}

	var config OIDCConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, nil // Invalid response, assume no OIDC
	}

	// Validate required fields
	if config.Issuer == "" || config.TokenEndpoint == "" {
		return nil, nil
	}

	return &config, nil
}

// DeviceAuthResponse represents the device authorization response.
type DeviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// OAuthFlow handles OAuth authentication flows.
type OAuthFlow struct {
	Config     *OIDCConfig
	ClientID   string
	Scopes     []string
	httpClient *http.Client
}

// NewOAuthFlow creates a new OAuth flow handler.
func NewOAuthFlow(config *OIDCConfig) *OAuthFlow {
	return &OAuthFlow{
		Config:     config,
		ClientID:   "plasmactl", // Default client ID for CLI tools
		Scopes:     []string{"openid", "email", "profile", "offline_access"},
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// DeviceAuth initiates the device authorization flow.
// This is the preferred flow for CLI tools as it doesn't require a redirect URI.
func (f *OAuthFlow) DeviceAuth(ctx context.Context) (*DeviceAuthResponse, error) {
	if f.Config.DeviceEndpoint == "" {
		return nil, fmt.Errorf("device authorization not supported by this provider")
	}

	data := url.Values{
		"client_id": {f.ClientID},
		"scope":     {strings.Join(f.Scopes, " ")},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.Config.DeviceEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device authorization failed with status %d", resp.StatusCode)
	}

	var authResp DeviceAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return nil, err
	}

	return &authResp, nil
}

// PollForToken polls the token endpoint waiting for user authorization.
func (f *OAuthFlow) PollForToken(ctx context.Context, deviceCode string, interval int) (*oauth2.Token, error) {
	if interval < 1 {
		interval = 5 // Default polling interval
	}

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			token, err := f.exchangeDeviceCode(ctx, deviceCode)
			if err != nil {
				// Check for "authorization_pending" or "slow_down" errors
				if strings.Contains(err.Error(), "authorization_pending") {
					continue // Keep polling
				}
				if strings.Contains(err.Error(), "slow_down") {
					interval += 5 // Increase interval
					ticker.Reset(time.Duration(interval) * time.Second)
					continue
				}
				return nil, err
			}
			return token, nil
		}
	}
}

func (f *OAuthFlow) exchangeDeviceCode(ctx context.Context, deviceCode string) (*oauth2.Token, error) {
	data := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {f.ClientID},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.Config.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Error        string `json:"error"`
		ErrorDesc    string `json:"error_description"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	if tokenResp.Error != "" {
		return nil, fmt.Errorf("%s: %s", tokenResp.Error, tokenResp.ErrorDesc)
	}

	token := &oauth2.Token{
		AccessToken:  tokenResp.AccessToken,
		TokenType:    tokenResp.TokenType,
		RefreshToken: tokenResp.RefreshToken,
	}
	if tokenResp.ExpiresIn > 0 {
		token.Expiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	return token, nil
}

// openBrowser opens the specified URL in the default browser.
func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return fmt.Errorf("unsupported platform")
	}
	return cmd.Start()
}

// generatePKCE generates a PKCE code verifier and challenge.
func generatePKCE() (verifier, challenge string, err error) {
	// Generate 32 random bytes for verifier
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)

	// Generate challenge using S256 method
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])

	return verifier, challenge, nil
}

// AuthCodeFlow performs the Authorization Code flow with PKCE.
// This flow opens a browser and starts a local HTTP server to receive the callback.
func (f *OAuthFlow) AuthCodeFlow(ctx context.Context, printer *launchr.Terminal) (*oauth2.Token, error) {
	if f.Config.AuthorizationEndpoint == "" {
		return nil, fmt.Errorf("authorization endpoint not available")
	}

	// Generate PKCE values
	verifier, challenge, err := generatePKCE()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PKCE: %w", err)
	}

	// Generate state for CSRF protection
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	// Find an available port for the callback server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to start callback server: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	// Build authorization URL
	authURL, err := url.Parse(f.Config.AuthorizationEndpoint)
	if err != nil {
		listener.Close()
		return nil, fmt.Errorf("invalid authorization endpoint: %w", err)
	}

	params := url.Values{
		"client_id":             {f.ClientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {strings.Join(f.Scopes, " ")},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	authURL.RawQuery = params.Encode()

	// Channel to receive the authorization code
	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)

	// Start the callback server
	server := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
	}
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		// Verify state
		if r.URL.Query().Get("state") != state {
			errCh <- fmt.Errorf("state mismatch")
			http.Error(w, "State mismatch", http.StatusBadRequest)
			return
		}

		// Check for error response
		if errMsg := r.URL.Query().Get("error"); errMsg != "" {
			errDesc := r.URL.Query().Get("error_description")
			errCh <- fmt.Errorf("authorization failed: %s: %s", errMsg, errDesc)
			http.Error(w, "Authorization failed", http.StatusBadRequest)
			return
		}

		// Get the authorization code
		code := r.URL.Query().Get("code")
		if code == "" {
			errCh <- fmt.Errorf("no authorization code received")
			http.Error(w, "No code received", http.StatusBadRequest)
			return
		}

		// Send success response to browser
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Authorization Successful</title></head>
<body style="font-family: sans-serif; text-align: center; padding: 50px;">
<h1>Authorization Successful</h1>
<p>You can close this window and return to the terminal.</p>
</body>
</html>`)

		codeCh <- code
	})

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Open browser to authorization URL
	printer.Info().Println("Opening browser for authentication...")
	if err := openBrowser(authURL.String()); err != nil {
		printer.Warning().Printf("Failed to open browser: %v\n", err)
		printer.Info().Println("Please open this URL manually:")
		printer.Println("  " + authURL.String())
	}
	printer.Println("")
	printer.Info().Println("Waiting for authorization...")

	// Wait for callback or timeout
	var code string
	select {
	case code = <-codeCh:
		// Success
	case err := <-errCh:
		server.Close()
		return nil, err
	case <-ctx.Done():
		server.Close()
		return nil, ctx.Err()
	case <-time.After(5 * time.Minute):
		server.Close()
		return nil, fmt.Errorf("authorization timeout")
	}

	// Shutdown the server
	server.Close()

	// Exchange code for token
	return f.exchangeAuthCode(ctx, code, verifier, redirectURI)
}

// exchangeAuthCode exchanges an authorization code for tokens.
func (f *OAuthFlow) exchangeAuthCode(ctx context.Context, code, verifier, redirectURI string) (*oauth2.Token, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {f.ClientID},
		"code_verifier": {verifier},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.Config.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Error        string `json:"error"`
		ErrorDesc    string `json:"error_description"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	if tokenResp.Error != "" {
		return nil, fmt.Errorf("%s: %s", tokenResp.Error, tokenResp.ErrorDesc)
	}

	token := &oauth2.Token{
		AccessToken:  tokenResp.AccessToken,
		TokenType:    tokenResp.TokenType,
		RefreshToken: tokenResp.RefreshToken,
	}
	if tokenResp.ExpiresIn > 0 {
		token.Expiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	return token, nil
}

// RefreshToken refreshes an expired OAuth token.
func (f *OAuthFlow) RefreshToken(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {f.ClientID},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.Config.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Error        string `json:"error"`
		ErrorDesc    string `json:"error_description"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	if tokenResp.Error != "" {
		return nil, fmt.Errorf("token refresh failed: %s: %s", tokenResp.Error, tokenResp.ErrorDesc)
	}

	token := &oauth2.Token{
		AccessToken:  tokenResp.AccessToken,
		TokenType:    tokenResp.TokenType,
		RefreshToken: tokenResp.RefreshToken,
	}
	if token.RefreshToken == "" {
		// Some providers don't return a new refresh token
		token.RefreshToken = refreshToken
	}
	if tokenResp.ExpiresIn > 0 {
		token.Expiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	return token, nil
}

// DoOAuthLogin performs OAuth authentication with the best available flow.
// It prefers Authorization Code flow (with browser) when available,
// falling back to Device Authorization flow for headless environments.
func DoOAuthLogin(ctx context.Context, baseURL string, printer *launchr.Terminal) (*CredentialsItem, error) {
	// Discover OIDC configuration
	config, err := DiscoverOIDC(ctx, baseURL)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil // No OAuth available
	}

	flow := NewOAuthFlow(config)
	printer.Info().Println("Discovered OAuth provider")

	var token *oauth2.Token

	// Try Authorization Code flow first (better UX with browser)
	if config.AuthorizationEndpoint != "" {
		token, err = flow.AuthCodeFlow(ctx, printer)
		if err != nil {
			printer.Warning().Printf("Browser auth failed: %v\n", err)
			// Fall through to try device flow
		}
	}

	// Fall back to Device Authorization flow if Authorization Code flow failed or unavailable
	if token == nil && config.DeviceEndpoint != "" {
		printer.Info().Println("Using device authorization flow...")
		token, err = doDeviceFlow(ctx, flow, config, printer)
		if err != nil {
			return nil, err
		}
	}

	// No OAuth flow available
	if token == nil {
		printer.Warning().Println("OAuth provider does not support any compatible authentication flow.")
		return nil, nil
	}

	printer.Success().Println("Authenticated via OAuth!")

	// Get username from userinfo endpoint if available
	username := "oauth-user"
	if config.UserinfoEndpoint != "" {
		if name, err := getUserInfo(ctx, config.UserinfoEndpoint, token.AccessToken); err == nil && name != "" {
			username = name
		}
	}

	// Create credentials item with OAuth data
	creds := &CredentialsItem{
		URL:           baseURL,
		Username:      username,
		AuthType:      AuthTypeOAuth,
		Issuer:        config.Issuer,
		AccessToken:   token.AccessToken,
		RefreshToken:  token.RefreshToken,
		TokenEndpoint: config.TokenEndpoint,
	}
	if !token.Expiry.IsZero() {
		creds.ExpiresAt = token.Expiry.Unix()
	}

	return creds, nil
}

// doDeviceFlow performs the Device Authorization flow.
func doDeviceFlow(ctx context.Context, flow *OAuthFlow, config *OIDCConfig, printer *launchr.Terminal) (*oauth2.Token, error) {
	deviceAuth, err := flow.DeviceAuth(ctx)
	if err != nil {
		return nil, fmt.Errorf("device authorization failed: %w", err)
	}

	// Display instructions to user
	printer.Println("")
	printer.Info().Println("To authorize, visit:")
	verificationURL := deviceAuth.VerificationURI
	if deviceAuth.VerificationURIComplete != "" {
		verificationURL = deviceAuth.VerificationURIComplete
	}
	printer.Println("  " + verificationURL)

	// Try to open browser automatically
	if err := openBrowser(verificationURL); err == nil {
		printer.Info().Println("(Browser opened automatically)")
	}

	if deviceAuth.VerificationURIComplete == "" {
		printer.Println("")
		printer.Info().Printf("And enter code: %s\n", deviceAuth.UserCode)
	}
	printer.Println("")
	printer.Info().Println("Waiting for authorization...")

	// Create a context with timeout based on device auth expiry
	pollCtx, cancel := context.WithTimeout(ctx, time.Duration(deviceAuth.ExpiresIn)*time.Second)
	defer cancel()

	// Poll for token
	token, err := flow.PollForToken(pollCtx, deviceAuth.DeviceCode, deviceAuth.Interval)
	if err != nil {
		return nil, fmt.Errorf("authorization failed: %w", err)
	}

	return token, nil
}

// getUserInfo fetches user information from the userinfo endpoint.
func getUserInfo(ctx context.Context, userinfoURL, accessToken string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("userinfo request failed with status %d", resp.StatusCode)
	}

	var userInfo struct {
		PreferredUsername string `json:"preferred_username"`
		Email             string `json:"email"`
		Name              string `json:"name"`
		Sub               string `json:"sub"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return "", err
	}

	// Return the best available username
	if userInfo.PreferredUsername != "" {
		return userInfo.PreferredUsername, nil
	}
	if userInfo.Email != "" {
		return userInfo.Email, nil
	}
	if userInfo.Name != "" {
		return userInfo.Name, nil
	}
	return userInfo.Sub, nil
}

// RefreshCredentials refreshes OAuth credentials if they are expired.
// Returns the updated credentials, whether refresh occurred, and any error.
func RefreshCredentials(ctx context.Context, creds CredentialsItem) (*CredentialsItem, bool, error) {
	// Only refresh OAuth credentials
	if creds.AuthType != AuthTypeOAuth {
		return &creds, false, nil
	}

	// Check if token is expired (with 5 minute buffer)
	if creds.ExpiresAt == 0 || time.Now().Unix() < creds.ExpiresAt-300 {
		return &creds, false, nil // Not expired yet
	}

	// No refresh token available
	if creds.RefreshToken == "" || creds.TokenEndpoint == "" {
		return &creds, false, fmt.Errorf("token expired and no refresh token available")
	}

	// Create a minimal OIDC config for refresh
	config := &OIDCConfig{
		Issuer:        creds.Issuer,
		TokenEndpoint: creds.TokenEndpoint,
	}

	flow := NewOAuthFlow(config)
	token, err := flow.RefreshToken(ctx, creds.RefreshToken)
	if err != nil {
		return &creds, false, fmt.Errorf("token refresh failed: %w", err)
	}

	// Update credentials with new token
	newCreds := creds
	newCreds.AccessToken = token.AccessToken
	newCreds.RefreshToken = token.RefreshToken
	if !token.Expiry.IsZero() {
		newCreds.ExpiresAt = token.Expiry.Unix()
	}

	return &newCreds, true, nil
}
