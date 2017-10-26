package secret

import (
	"encoding/binary"
	"io"
	"io/ioutil"

	"github.com/pkg/errors"
)

const revSize = 2

type osFile interface {
	io.Reader
	io.Writer
	io.Closer
	io.Seeker

	Truncate(size int64) error
}

type file struct {
	rw osFile
}

func newFile(f osFile) *file {
	return &file{rw: f}
}

func (f *file) readRevision() (uint16, error) {
	if _, err := f.rw.Seek(0, io.SeekStart); err != nil {
		return 0, errors.Wrap(err, "cannot seek to the revision")
	}
	buf := make([]byte, revSize, revSize)
	if n, err := f.rw.Read(buf); err != nil {
		return 0, errors.Wrap(err, "cannot read revision")
	} else if n != revSize {
		return 0, errors.Wrap(err, "revision number is truncated")
	}
	return binary.LittleEndian.Uint16(buf), nil
}

func (f *file) readSalt() ([]byte, error) {
	if _, err := f.rw.Seek(revSize, io.SeekStart); err != nil {
		return nil, errors.Wrap(err, "cannot seek seek to the salt")
	}
	buf := make([]byte, pbkdf2Size, pbkdf2Size)
	if n, err := f.rw.Read(buf); err != nil {
		return nil, errors.Wrap(err, "cannot read salt")
	} else if n != pbkdf2Size {
		return nil, errors.Wrap(err, "salt is truncated")
	}
	return buf, nil
}

func (f *file) readData() (encryptedData, error) {
	if _, err := f.rw.Seek(revSize+pbkdf2Size, io.SeekStart); err != nil {
		return nil, errors.Wrap(err, "cannot seek to the data")
	}
	data, err := ioutil.ReadAll(f.rw)
	if err != nil {
		return nil, errors.Wrap(err, "cannot read data")
	}
	return encryptedData(data), nil
}

func (f *file) writeRevision(rev uint16) error {
	buf := make([]byte, revSize, revSize)
	binary.LittleEndian.PutUint16(buf, rev)
	if _, err := f.rw.Seek(0, io.SeekStart); err != nil {
		return errors.Wrap(err, "cannot seek to the revision")
	}
	if _, err := f.rw.Write(buf); err != nil {
		return errors.Wrap(err, "cannot write revision")
	}
	return nil
}

func (f *file) writeSalt(salt []byte) error {
	if len(salt) != pbkdf2Size {
		return errors.Errorf("invalid salt length %d; want %d", len(salt), pbkdf2Size)
	}
	if _, err := f.rw.Seek(revSize, io.SeekStart); err != nil {
		return errors.Wrap(err, "cannot seek to the revision")
	}
	if _, err := f.rw.Write(salt); err != nil {
		return errors.Wrap(err, "cannot write salt")
	}
	return nil
}

func (f *file) writeData(data encryptedData) error {
	if err := f.rw.Truncate(revSize + pbkdf2Size); err != nil {
		return errors.Wrap(err, "cannot truncate file")
	}
	if _, err := f.rw.Seek(revSize+pbkdf2Size, io.SeekStart); err != nil {
		return errors.Wrap(err, "cannot seek to data")
	}
	if _, err := f.rw.Write([]byte(data)); err != nil {
		return errors.Wrap(err, "cannot write data")
	}
	return nil
}

func (f *file) close() error {
	return f.rw.Close()
}
