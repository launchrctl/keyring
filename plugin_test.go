package keyring

import (
	"testing"

	"github.com/launchrctl/launchr"
	"github.com/stretchr/testify/require"

	"github.com/launchrctl/launchr/pkg/action"
)

const testActionYaml = `
runtime: plugin
action:
  title: test keyring
  options:
    - name: secret
      process:
        - processor: keyring.GetKeyValue
          options:
            key: storedsecret
`

const testActionYamlWithDefault = `
runtime: plugin
action:
  title: test keyring
  options:
    - name: secret
      default: "mydefault"
      process:
        - processor: keyring.GetKeyValue
          options:
            key: storedsecret
`

const testActionYamlMissing = `
runtime: plugin
action:
  title: test keyring
  options:
    - name: secret
      default: "mydefault"
      process:
        - processor: keyring.GetKeyValue
          options:
            key: missing_key
`

const testActionYamlWrongOptions = `
runtime: plugin
action:
  title: test keyring
  options:
    - name: secret
      process:
        - processor: keyring.GetKeyValue
`

func Test_KeyringProcessor(t *testing.T) {
	// Prepare services.
	k := &keyringService{
		store: &dataStoreYaml{file: &plainFile{fname: "teststorage.yaml"}},
		mask:  &launchr.SensitiveMask{},
	}
	am := action.NewManager()
	addValueProcessors(am, k)

	// Prepare test data.
	expected := "my_secret"
	err := k.AddItem(KeyValueItem{Key: "storedsecret", Value: expected})
	require.NoError(t, err)

	expConfig := action.InputParams{
		"secret": expected,
	}
	expGiven := action.InputParams{
		"secret": "my_user_secret",
	}
	tt := []action.TestCaseValueProcessor{
		{Name: "get keyring keyvalue - no input given", Yaml: testActionYaml, ExpOpts: expConfig},
		{Name: "get keyring keyvalue - default and no input given", Yaml: testActionYamlWithDefault, ExpOpts: expConfig},
		{Name: "get keyring keyvalue - input given", Yaml: testActionYaml, Opts: expGiven, ExpOpts: expGiven},
		{Name: "get keyring keyvalue - missing key", Yaml: testActionYamlMissing, ErrProc: buildNotFoundError("missing_key", errTplNotFoundKey, ErrNotFound)},
		{Name: "get keyring keyvalue - wrong options", Yaml: testActionYamlWrongOptions, ErrInit: action.ErrValueProcessorOptionsFieldValidation{Field: "key", Reason: "required"}},
	}
	for _, tt := range tt {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			tt.Test(t, am)
		})
	}
}
