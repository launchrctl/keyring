package keyring

import (
	"io"
	"os"

	"filippo.io/age"
)

// CredentialsFile is an interface to open and edit credentials file.
type CredentialsFile interface {
	io.ReadWriteCloser
	Open(flag int, perm os.FileMode) error
}

type plainFile struct {
	fname string
	file  io.ReadWriteCloser
}

func (f *plainFile) Open(flag int, perm os.FileMode) (err error) {
	// Filename comes from a Keyring and already cleaned
	f.file, err = os.OpenFile(f.fname, flag, perm) //nolint:gosec
	if err != nil {
		return err
	}

	return nil
}

func (f *plainFile) Read(p []byte) (n int, err error) {
	return f.file.Read(p)
}

func (f *plainFile) Write(p []byte) (n int, err error) {
	return f.file.Write(p)
}

func (f *plainFile) Close() error {
	return f.file.Close()
}

type ageFile struct {
	file       *plainFile
	askPass    AskPass
	passphrase string // @todo make sure it's compatible with ACL in the future

	r io.Reader
	w io.WriteCloser
}

func newAgeFile(fname string, askPass AskPass) CredentialsFile {
	return &ageFile{
		file: &plainFile{
			fname: fname + ".age",
		},
		askPass: askPass,
	}
}

func (f *ageFile) Open(flag int, perm os.FileMode) (err error) {
	return f.file.Open(flag, perm)
}

func (f *ageFile) Read(p []byte) (n int, err error) {
	if f.passphrase == "" {
		f.passphrase, err = f.askPass.GetPass()
		if err != nil {
			return 0, err
		}
	}
	if f.r == nil {
		id, _ := age.NewScryptIdentity(f.passphrase)
		f.r, _ = age.Decrypt(f.file, id)
	}
	return f.r.Read(p)
}

func (f *ageFile) Write(p []byte) (n int, err error) {
	if f.passphrase == "" {
		f.passphrase, err = f.askPass.NewPass()
		if err != nil {
			return 0, err
		}
	}
	if f.w == nil {
		rcp, _ := age.NewScryptRecipient(f.passphrase)
		f.w, _ = age.Encrypt(f.file, rcp)
	}
	return f.w.Write(p)
}

func (f *ageFile) Close() error {
	if f.w != nil {
		_ = f.w.Close()
	}
	return f.file.Close()
}
