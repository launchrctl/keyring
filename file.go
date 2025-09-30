package keyring

import (
	"errors"
	"io"
	"io/fs"
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
	Open(flag int, perm fs.FileMode) error
	// Unlock decrypts a file if supported.
	Unlock(askNew bool) error
	// Lock makes it to request Unlock again.
	Lock()
	// Remove deletes a file from FS.
	Remove() error
	// Stat returns a [FileInfo] describing the named file.
	// If there is an error, it will be of type [*PathError].
	// See os.Stat().
	Stat() (fs.FileInfo, error)
}

type nullFile struct{}

func (nullFile) Stat() (fs.FileInfo, error)            { return nil, fs.ErrNotExist }
func (nullFile) Open(_ int, _ os.FileMode) (err error) { return nil }
func (nullFile) Unlock(_ bool) error                   { return nil }
func (nullFile) Lock()                                 {}
func (nullFile) Read(_ []byte) (int, error)            { return 0, io.EOF }
func (nullFile) Write(p []byte) (int, error)           { return len(p), nil }
func (nullFile) Close() error                          { return nil }
func (nullFile) Remove() error                         { return nil }

type plainFile struct {
	fname string
	file  io.ReadWriteCloser
}

// NewPlainFile creates a CredentialsFile to open a plain file.
func NewPlainFile(fname string) CredentialsFile {
	return &plainFile{
		fname: fname,
	}
}

func (f *plainFile) Open(flag int, perm fs.FileMode) (err error) {
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

func (f *plainFile) Stat() (fs.FileInfo, error)        { return os.Stat(f.fname) }
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
	*plainFile
	askPass    AskPass
	passphrase string // @todo make sure it's compatible with ACL in the future

	r io.Reader
	w io.WriteCloser
}

// NewAgeFile creates a CredentialsFile to open a file encrypted with age.
func NewAgeFile(fname string, askPass AskPass) CredentialsFile {
	return &ageFile{
		plainFile: NewPlainFile(fname).(*plainFile),
		askPass:   askPass,
	}
}

func (f *ageFile) Lock() { f.passphrase = "" }

func (f *ageFile) Unlock(askNew bool) (err error) {
	if f.passphrase != "" {
		return nil
	}
	if askNew {
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
			} else if strings.Contains(err.Error(), "no identity matched any of the recipients") {
				return 0, ErrIncorrectPass
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
	var err error
	if f.w != nil {
		err = f.w.Close()
	}
	f.w = nil
	f.r = nil
	return errors.Join(err, f.file.Close())
}
