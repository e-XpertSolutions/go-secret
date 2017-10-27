package secret

import (
	"crypto/cipher"
	"os"
	"sync"

	"github.com/pkg/errors"
)

// CurrentRevision represents the version of the store format.
// The value must be incremented for every a change that breaks the
// compatibility with the existing binary format.
const CurrentRevision uint16 = 1

// ErrNotFound is returned by Get when the key does not exist in the store.
var ErrNotFound = errors.New("record not found")

// A Store holds key/value pairs that are securely stored into an encrypted file
// on disk. The store is safe for concurrent use.
type Store struct {
	f   *file
	rev uint16
	gcm cipher.AEAD
	mu  sync.RWMutex
}

// OpenStore opens an existing store located at the given path and protected
// with the given passphrase.
//
// If the store does not exist, it creates a new one at the path and protected
// with the passphrase.
func OpenStore(path, passphrase string) (*Store, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return newStore(path, passphrase)
		}
		return nil, errors.Wrapf(err, "cannot stat store path %q", path)
	}
	return openStore(path, passphrase)
}

func newStore(path, passphrase string) (*Store, error) {
	osf, err := os.Create(path)
	if err != nil {
		return nil, errors.Wrap(err, "error while creating new secret store")
	}
	salt, err := generateSalt()
	if err != nil {
		_ = osf.Close()
		return nil, errors.Wrap(err, "error while create new secret store")
	}
	f := newFile(osf)
	if err := f.writeRevision(CurrentRevision); err != nil {
		return nil, errors.Wrap(err, "error while creating new secret store")
	}
	if err := f.writeSalt(salt); err != nil {
		return nil, errors.Wrap(err, "error while creating new secret store")
	}
	gcm, err := newGCM(newKey([]byte(passphrase), salt))
	if err != nil {
		return nil, errors.Wrap(err, "cannot open secret store")
	}
	return &Store{f: f, rev: CurrentRevision, gcm: gcm}, nil
}

func openStore(path, passphrase string) (*Store, error) {
	osf, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		return nil, errors.Wrap(err, "cannot open secret store")
	}
	f := newFile(osf)
	rev, err := f.readRevision()
	if err != nil {
		return nil, errors.Wrap(err, "cannot open secret store")
	}
	salt, err := f.readSalt()
	if err != nil {
		return nil, errors.Wrap(err, "cannot open secret store")
	}
	gcm, err := newGCM(newKey([]byte(passphrase), salt))
	if err != nil {
		return nil, errors.Wrap(err, "cannot open secret store")
	}
	return &Store{
		f:   f,
		rev: rev,
		gcm: gcm,
	}, nil
}

// Get returns the value in the store for a key. If no value is present,
// ErrNotFound returned.
func (s *Store) Get(key string) ([]byte, error) {
	s.mu.RLock()
	data, err := s.f.readData()
	s.mu.RUnlock()
	if err != nil {
		return nil, errors.Wrap(err, "impossible to retrieve data")
	}
	if len(data) == 0 {
		return nil, ErrNotFound
	}
	decryptedData, err := s.decrypt(data)
	if err != nil {
		return nil, errors.Wrap(err, "impossible to retrieve data")
	}
	hm, err := decodeHmap(decryptedData)
	if err != nil {
		return nil, errors.Wrap(err, "cannot decode hmap")
	}
	value := hm.load(key)
	if value == nil {
		return nil, ErrNotFound
	}
	return value, nil
}

// Put sets the value for a key in the store. The value must not be nil but can
// be empty.
func (s *Store) Put(key string, value []byte) error {
	if value == nil {
		return errors.New("value is nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var hm *hmap

	data, err := s.f.readData()
	if err != nil {
		return errors.Wrap(err, "impossible to retrieve data")
	}
	if len(data) != 0 {
		decryptedData, err := s.decrypt(data)
		if err != nil {
			return errors.Wrap(err, "impossible to retrieve data")
		}
		hm, err = decodeHmap(decryptedData)
		if err != nil {
			return errors.Wrap(err, "cannot decode hmap")
		}
	} else {
		hm = &hmap{m: make(map[string][]byte)}
	}

	if err := hm.store(key, value); err != nil {
		return errors.Wrap(err, "impossible to put data")
	}

	encryptedData, err := s.encrypt(hm.encode())
	if err != nil {
		return errors.Wrap(err, "impossible to put data")
	}

	err = s.f.writeData(encryptedData)
	if err != nil {
		return errors.Wrap(err, "impossible to put data")
	}
	return nil
}

// Delete deletes the value for a key in the store. If the key does not exist
// no error is returned.
func (s *Store) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := s.f.readData()
	if err != nil {
		return errors.Wrap(err, "impossible to retrieve data")
	}
	if len(data) == 0 {
		return nil
	}

	decryptedData, err := s.decrypt(data)
	if err != nil {
		return errors.Wrap(err, "impossible to retrieve data")
	}

	hm, err := decodeHmap(decryptedData)
	if err != nil {
		return errors.Wrap(err, "cannot decode hmap")
	}

	hm.delete(key)

	encryptedData, err := s.encrypt(hm.encode())
	if err != nil {
		return errors.Wrap(err, "impossible to put data")
	}

	err = s.f.writeData(encryptedData)
	if err != nil {
		return errors.Wrap(err, "impossible to put data")
	}

	return nil
}

// Keys lists all the keys stored in the store.
func (s *Store) Keys() ([]string, error) {
	s.mu.RLock()
	data, err := s.f.readData()
	s.mu.RUnlock()
	if err != nil {
		return nil, errors.Wrap(err, "impossible to retrieve data")
	}
	if len(data) == 0 {
		return []string{}, nil
	}
	decryptedData, err := s.decrypt(data)
	if err != nil {
		return nil, errors.Wrap(err, "impossible to retrieve data")
	}
	hm, err := decodeHmap(decryptedData)
	if err != nil {
		return nil, errors.Wrap(err, "cannot decode hmap")
	}
	return hm.keys(), nil
}

// Revision returns the current revision of the store.
func (s *Store) Revision() uint16 {
	return s.rev
}

// Close closes the store encrypted file.
func (s *Store) Close() error {
	if err := s.f.close(); err != nil {
		return errors.Wrap(err, "cannot close encrypted file")
	}
	return nil
}

func (s *Store) encrypt(plaintext []byte) (encryptedData, error) {
	var err error
	defer func() {
		if r := recover(); r != nil {
			err = errors.Wrap(err, "cannot encrypt plaintext")
		}
	}()

	nonce, err := generateNonce(s.gcm.NonceSize())
	if err != nil {
		return nil, errors.Wrap(err, "cannot encrypt plaintext")
	}

	var ciphertext []byte
	ciphertext = s.gcm.Seal(ciphertext, nonce, plaintext, nil)

	return newEncryptedData(nonce, ciphertext), err
}

func (s *Store) decrypt(data encryptedData) ([]byte, error) {
	var (
		plaintext []byte
		err       error
	)
	plaintext, err = s.gcm.Open(plaintext, data.nonce(), data.ciphertext(), nil)
	if err != nil {
		return nil, errors.Wrap(err, "cannot decrypt ciphertext")
	}
	return plaintext, nil
}
