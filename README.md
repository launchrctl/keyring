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

To add a new key-value pair with an interactive shell:
```shell
launchr keyring:set your-key
```

It's possible to parse a user value and store it as a struct in a keyring. Supported formats are [string, yaml, json]:
```shell
launchr keyring:set your-key value
```

It's possible to parse a user value and store it as a struct in a keyring. Possible formats are [string, yaml, json]:
```shell
launchr keyring:set key --format yaml -- "- name: test-1
- name: test-2"
launchr keyring:set key --format yaml -- "$(cat file.yaml)"
launchr keyring:set key --format json -- '[
  {
    "name": "test-1"
  },
  {
    "name": "test-2"
  }
]'
launchr keyring:set key --format json -- "$(cat file.json)"
```

You can dynamically build JSON\YAML wit structures and pass them directly to the command: `jq`
```shell
# Define your variables
TOKEN1="abc123def456"
NAME1="production-api-key"
CREATED1="2025-01-15T10:30:00Z"

TOKEN2="xyz789uvw012"
NAME2="development-token"
CREATED2="2025-01-15T11:45:00Z"
EXPIRES2="2025-07-15T11:45:00Z"

launchr keyring:set api-tokens-json --format json -- "$(jq -n \
  --arg t1 "$TOKEN1" --arg n1 "$NAME1" --arg c1 "$CREATED1" \
  --arg t2 "$TOKEN2" --arg n2 "$NAME2" --arg c2 "$CREATED2" --arg e2 "$EXPIRES2" \
  '[
    {
      tokenhash: $t1,
      name: $n1,
      created: $c1,
      expires: null
    },
    {
      tokenhash: $t2,
      name: $n2,
      created: $c2,
      expires: $e2
    }
  ]')"
```
`yq` using same variables:
```shell
launchr keyring:set api-tokens-yaml --format yaml -- "$(yq -n \
  '.[0].tokenhash = env(TOKEN1) |
   .[0].name = env(NAME1) |
   .[0].created = env(CREATED1) |
   .[0].expires = null |
   .[1].tokenhash = env(TOKEN2) |
   .[1].name = env(NAME2) |
   .[1].created = env(CREATED2) |
   .[1].expires = env(EXPIRES2)')"
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
	app.GetService(k)
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