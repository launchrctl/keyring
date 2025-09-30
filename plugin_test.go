package keyring

import (
	"path/filepath"
	"testing"

	"github.com/launchrctl/launchr"
	"github.com/launchrctl/launchr/pkg/action"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

const testActionTplFuncValid = `
action:
  title: test keyring
runtime:
  type: container
  image: alpine
  command:
    - '{{ keyring "storedsecret" }}'
`

const testActionTplFuncNotFound = `
action:
  title: test keyring
runtime:
  type: container
  image: alpine
  command:
    - '{{ keyring "notexist" }}'
`

const testActionTplFuncBadArgs = `
action:
  title: test keyring
runtime:
  type: container
  image: alpine
  command:
    - '{{ keyring "storedsecret" "storedsecret" }}'
`

func Test_KeyringProcessor(t *testing.T) {
	// Prepare services.
	k := NewService(NewFileStore(nil), nil)
	am := action.NewManager()
	tp := action.NewTemplateProcessors()
	addTemplateProcessors(tp, k)

	// Prepare test data.
	expected := "my_secret" //nolint:goconst // Duplicated constant is ok for tests.
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
			tt.Test(t, am, tp)
		})
	}
}

func Test_KeyringTemplate(t *testing.T) {
	// Prepare services.
	k := NewService(NewFileStore(nil), nil)
	tp := action.NewTemplateProcessors()
	addTemplateProcessors(tp, k)
	svc := launchr.NewServiceManager()
	svc.Add(tp)

	// Prepare test data.
	expected := "my_secret"
	err := k.AddItem(KeyValueItem{Key: "storedsecret", Value: expected})
	require.NoError(t, err)

	type testCase struct {
		Name string
		Yaml string
		Exp  []string
		Err  string
	}
	tt := []testCase{
		{Name: "valid", Yaml: testActionTplFuncValid, Exp: []string{expected}},
		{Name: "key not found", Yaml: testActionTplFuncNotFound, Err: "\"notexist\" not found in keyring"},
		{Name: "wrong call", Yaml: testActionTplFuncBadArgs, Err: "wrong number of args for keyring: want 1 got 2"},
	}
	for _, tt := range tt {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			a := action.NewFromYAML(tt.Name, []byte(tt.Yaml))
			a.SetServices(svc)
			err := a.EnsureLoaded()
			if tt.Err != "" {
				require.ErrorContains(t, err, tt.Err)
				return
			}
			require.NoError(t, err)
			rdef := a.RuntimeDef()
			assert.Equal(t, tt.Exp, []string(rdef.Container.Command))
		})
	}
}

func Test_KeyringSave(t *testing.T) {
	type testCase struct {
		name      string
		dataStore func(string) DataStore
	}
	tt := []testCase{
		{"plain file", func(dir string) DataStore {
			return NewFileStore(
				NewPlainFile(filepath.Join(dir, defaultFileYaml)),
			)
		}},
		{"age file", func(dir string) DataStore {
			testPass := persistentPassphrase{pass: "pass"}
			return NewFileStore(
				NewAgeFile(
					filepath.Join(dir, defaultFileYaml+".age"),
					AskPassConst(testPass.get),
				),
			)
		}},
	}
	for _, tt := range tt {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Init test keyring service.
			dir := t.TempDir()
			keyring := NewService(tt.dataStore(dir), nil)

			// Add an item and save.
			err := keyring.AddItem(KeyValueItem{Key: "foo", Value: "bar"})
			require.NoError(t, err)
			err = keyring.Save()
			require.NoError(t, err)

			// Try adding another item after save.
			err = keyring.AddItem(KeyValueItem{Key: "bar", Value: "buz"})
			require.NoError(t, err)
			err = keyring.Save()
			require.NoError(t, err)

			// Check the content of the keyring.
			assertKeyringVals := func() {
				val1, err := keyring.GetForKey("foo")
				assert.NoError(t, err)
				assert.Equal(t, "bar", val1.Value.(string))

				val2, err := keyring.GetForKey("bar")
				assert.NoError(t, err)
				assert.Equal(t, "buz", val2.Value.(string))
			}
			assertKeyringVals()

			// Try to recreate a service and make sure that the content is definitely loaded from the disk.
			keyring = NewService(tt.dataStore(dir), nil)
			// Check the content of the keyring.
			assertKeyringVals()
		})
	}
}
