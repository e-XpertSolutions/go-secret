package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"

	"github.com/pkg/errors"
	"golang.org/x/crypto/pbkdf2"
)

const keySize = 32

const (
	pbkdf2Size = 32
	pbkdf2Iter = 20000
)

// standard GCM nonce size
const nonceSize = 12

type encryptedData []byte

func newEncryptedData(nonce, ciphertext []byte) encryptedData {
	data := make(encryptedData, len(nonce)+len(ciphertext))
	copy(data[:len(nonce)], nonce)
	copy(data[len(nonce):], ciphertext)
	return data
}

func (data encryptedData) nonce() []byte {
	if len(data) < nonceSize+1 {
		return []byte{}
	}
	return data[0:nonceSize]
}

func (data encryptedData) ciphertext() []byte {
	if len(data) < nonceSize+1 {
		return []byte{}
	}
	return data[nonceSize:]
}

func newKey(passphrase, salt []byte) []byte {
	return pbkdf2.Key(passphrase, salt, pbkdf2Iter, pbkdf2Size, sha256.New)
}

func generateSalt() ([]byte, error) {
	salt := make([]byte, pbkdf2Size, pbkdf2Size)
	if _, err := rand.Read(salt); err != nil {
		return nil, errors.Wrap(err, "cannot generate salt")
	}
	return salt, nil
}

func generateNonce(nonceSize int) ([]byte, error) {
	nonce := make([]byte, nonceSize, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.Wrap(err, "cannot generate nonce")
	}
	return nonce, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create new aes block cipher")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create new gcm cipher")
	}
	return gcm, nil
}
