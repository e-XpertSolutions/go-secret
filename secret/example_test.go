package secret_test

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/e-XpertSolutions/go-secret/secret"
)

func Example() {
	path := filepath.Join(os.TempDir(), "secret.store")
	defer os.Remove(path)

	passphrase := "strong_passphrase"

	// Open the secret store. Since it does not exist, it will create it.
	store, err := secret.OpenStore(path, passphrase)
	if err != nil {
		log.Print("[error] ", err)
		return
	}
	defer store.Close()

	// Store a password.
	err = store.Put("password", []byte("my_very_secret_password"))
	if err != nil {
		log.Print("[error] ", err)
		return
	}

	// List all keys present in the store, which should only be "password" in
	// this case.
	keys, err := store.Keys()
	if err != nil {
		log.Print("[error] ", err)
		return
	}

	fmt.Println("Keys:", keys)

	// Retrieve the stored password.
	value, err := store.Get("password")
	if err != nil {
		log.Print("[error] ", err)
		return
	}

	fmt.Println("Retrieved password:", string(value))

	fmt.Println("Delete password")

	// Delete the password from the store.
	err = store.Delete("password")
	if err != nil {
		log.Print("[error] ", err)
		return
	}

	//  Since "password" has been deleted, there should be no keys in the store.
	keys, err = store.Keys()
	if err != nil {
		log.Print("[error] ", err)
		return
	}

	fmt.Println("Keys:", keys)

	// Output:
	// Keys: [password]
	// Retrieved password: my_very_secret_password
	// Delete password
	// Keys: []
}
