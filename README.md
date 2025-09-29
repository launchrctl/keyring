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
# Input passphrase directly
launchr login \
  --url=https://your.gitlab.com \
  --username=USER \
  --password=SECRETPASSWORD \
  --keyring-passphrase=YOURPASSHRPASE

# Get passphrase from a file
launchr login \
  --url=https://your.gitlab.com \
  --username=USER \
  --password=SECRETPASSWORD \
  --keyring-passphrase-file=/path/to/your/secret
```

Flags `--keyring-passphrase` and `--keyring-passphrase-file` are available for all launchr commands, for example:
```shell
launchr compose --keyring-passphrase=YOURPASSHRPASE
launchr compose --keyring-passphrase-file=/path/to/your/secret
```

These flags may be passed as environment variables `LAUNCHR_KEYRING_PASSPHRASE` and `LAUNCHR_KEYRING_PASSPHRASE_FILE`:
```shell
LAUNCHR_KEYRING_PASSPHRASE=YOURPASSHRPASE launchr compose
LAUNCHR_KEYRING_PASSPHRASE_FILE=/path/to/your/secret launchr compose
```

Flags and environment variables are taken in the following priority:
1. `--keyring-passphrase`
2. `LAUNCHR_KEYRING_PASSPHRASE`
3. `--keyring-passphrase-file`
4. `LAUNCHR_KEYRING_PASSPHRASE_FILE`

**NB:** If the binary is created with a specific app name like `myappname`, the variable name will change accordingly `MYAPPNAME_KEYRING_PASSPHRASE_FILE`.  

Flag `--keyring-passphrase-file` will also set `LAUNCHR_KEYRING_PASSPHRASE_FILE` for subprocesses.  
These environment variables are inherited in subprocesses.  
Using `--keyring-passphrase-file` or `LAUNCHR_KEYRING_PASSPHRASE_FILE` is a preferred way to pass the secret because the secret won't be exposed.

To delete an item from the keyring:
```shell
launchr logout URL
launchr logout --all
```

The file is created in `.launchr/keyring.yaml.age`.  
The content may be viewed/edited with age cli:
```shell
age -d .launchr/keyring.yaml.age
age -p .launchr/keyring.yaml > .launchr/keyring.yaml.age
```

## In code

Add a module dependency:
```shell
go get -u github.com/launchrctl/keyring
```

To use the keyring in code, get the service from the app:
```go
package main

import (
	"github.com/launchrctl/keyring"
	"github.com/launchrctl/launchr"
)

func GetPassword(app launchr.App, url string) (keyring.CredentialsItem, error) {
	// Get the service by type from the app.
	var k keyring.Keyring
	app.Services().Get(k)
	// Get by url. Error if the keyring could not be unlocked.
	// Error keyring.ErrNotFound is returned if an item was not found.
	creds, err := k.GetForURL(url)
	if err != nil {
		return keyring.CredentialsItem{}, err
	}
	return creds, nil
}
```

Include with launchr build:
```shell
launchr build -p github.com/launchrctl/keyring
```