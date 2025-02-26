package keyring

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/launchrctl/launchr"
)

// CredentialsFile is an interface to open and edit credentials file.
type CredentialsFile interface {
	io.ReadWriteCloser
	// Open opens a file in FS with flag open options and perm for file permissions if the file is new.
	// See os.OpenFile for more info about flag and perm arguments.
	Open(flag int, perm os.FileMode) error
	// Unlock decrypts a file if supported.
	Unlock(bool) error
	// Lock makes it to request Unlock again.
	Lock()
	// Remove deletes a file from FS.
	Remove() error
}

type plainFile struct {
	fname string
	file  io.ReadWriteCloser
}

func (f *plainFile) Open(flag int, perm os.FileMode) (err error) {
	isCreate := flag&os.O_CREATE == os.O_CREATE
	if isCreate {
		err = launchr.EnsurePath(filepath.Dir(f.fname))
		if err != nil {
			return err
		}
	}
	file, err := os.OpenFile(f.fname, flag, perm) //nolint:gosec
	if err != nil {
		return err
	}
	f.file = file

	return nil
}

func (f *plainFile) Unlock(bool) (err error)           { return nil }
func (f *plainFile) Lock()                             {}
func (f *plainFile) Read(p []byte) (n int, err error)  { return f.file.Read(p) }
func (f *plainFile) Write(p []byte) (n int, err error) { return f.file.Write(p) }
func (f *plainFile) Close() error                      { return f.file.Close() }
func (f *plainFile) Remove() (err error) {
	err = os.Remove(f.fname)
	if os.IsNotExist(err) {
		return nil
	}
	return err
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

func (f *ageFile) Open(flag int, perm os.FileMode) (err error) { return f.file.Open(flag, perm) }
func (f *ageFile) Remove() error                               { return f.file.Remove() }
func (f *ageFile) Lock()                                       { f.passphrase = "" }

func (f *ageFile) Unlock(pass bool) (err error) {
	if f.passphrase != "" {
		return nil
	}
	if pass {
		f.passphrase, err = f.askPass.NewPass()
	} else {
		f.passphrase, err = f.askPass.GetPass()
	}
	if err != nil {
		return err
	}
	if f.passphrase == "" {
		return ErrEmptyPass
	}
	return nil
}

func (f *ageFile) Read(p []byte) (n int, err error) {
	if f.passphrase == "" {
		panic("call Unlock first")
	}
	if f.r == nil {
		// Error shouldn't appear because the passphrase is not empty.
		id, _ := age.NewScryptIdentity(f.passphrase)
		f.r, err = age.Decrypt(f.file, id)
		if err != nil {
			// The file is malformed, not age encrypted and can't be read.
			if strings.Contains(err.Error(), "parsing age header:") {
				return 0, ErrKeyringMalformed
			}
			return 0, err
		}
	}
	return f.r.Read(p)
}

func (f *ageFile) Write(p []byte) (n int, err error) {
	if f.passphrase == "" {
		panic("call Unlock first")
	}
	if f.w == nil {
		// Error shouldn't appear because the passphrase is not empty.
		rcp, _ := age.NewScryptRecipient(f.passphrase)
		f.w, err = age.Encrypt(f.file, rcp)
		if err != nil {
			return 0, err
		}
	}
	return f.w.Write(p)
}

func (f *ageFile) Close() error {
	if f.w != nil {
		_ = f.w.Close()
	}
	return f.file.Close()
}
