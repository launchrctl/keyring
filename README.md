# Launchr Keyring

**Keyring** is a launchr plugin and a service providing a password storage functionality encrypted with [age](https://github.com/FiloSottile/age).
The storage is encrypted with a passphrase.

## How to use

To add a new item with an interactive shell:
```shell
launchr login
```

If an interactive shell is not available, credentials may be provided with flags:
```shell
launchr login \
  --url=https://your.gitlab.com \
  --username=USER \
  --password=SECRETPASSWORD \
  --keyring-passphrase=YOURPASSHRPASE
```

Flag `--keyring-passphrase` is available for all launchr commands, for example:
```shell
launchr compose --keyring-passphrase=YOURPASSHRPASE
```

To delete an item from the keyring:
```shell
launchr logout URL
```

The file is created in `.launchr/keyring.yaml.age`.  
The content may be viewed/edited with age cli:
```shell
age -d .launchr/keyring.yaml.age
age -p .launchr/keyring.yaml > .launchr/keyring.yaml.age
```

## In code

Include with launchr build:
```shell
launchr build -p github.com/launchrctl/keyring
```

To use the keyring in code, get the service from the app:
```go
package main

import (
	"github.com/launchrctl/keyring"
	"github.com/launchrctl/launchr"
)

func GetPassword(app *launchr.App, url string) (keyring.CredentialsItem, error) {
	// Get the service by type from the app.
	k := launchr.GetService[keyring.Keyring](app)
	// Get by url. Error if the keyring could not be unlocked.
	// Error keyring.ErrNotFound is returned if an item was not found.
	creds, err := k.GetForURL(url)
	if err != nil {
		return keyring.CredentialsItem{}, err
	}
	return creds, nil
}

```