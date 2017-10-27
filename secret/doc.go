/*
Package secret provides a library to safely store key/value pairs into an
encrypted file on disk.


Encryption

The data are encrypted using AES-256 and the GCM (Galois/Counter Mode) mode.
The encryption key is derived from the store passphrase using the PBKDF2
algorithm.


Binary Format

The secret store uses the following binary format:

   2 bytes for the revision stored as an unsigned int on 16bits encoded in
   little endian

   32 bytes for the salt used by key derivation algorithm (PBKDF2)

   All other bytes are used to store the encrypted data. There is no limit for
   the size. The first 12 bytes are used to store the nonce required by the
   AES-GCM cipher.

Before the encryption, the key/value pairs are encoded using the following
format:

   {key:base64(value)}

The key can only contains alphanumeric characters, dashes ("-") and
underscores ("_"). The value has no limitation and is encoded using standard
base 64 encoding.


Limitation

The store is not optimized for huge amount of data nor for high performance.


Security

All the security relies on the passphrase. It is therefore highly recommended
to use a strong passphrase, preferably generated with a strong generator.
*/
package secret
