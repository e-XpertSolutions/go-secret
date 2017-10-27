package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"e-xpert_solutions/go-secret/secret"

	"github.com/howeyc/gopass"
)

func usage() {
	fmt.Fprint(os.Stderr, "Gosecret is command line tool to manage an encrypted key/value store.\n\n")
	fmt.Fprint(os.Stderr, "Usage:\n\n\tgosecret [STORE FILE] [COMMAND] [ARGS...]\n\n")
	fmt.Fprint(os.Stderr, `The commands are:

put    store a new key/value pair in the secret store. This command requires 2
       arguments: [KEY] [VALUE]. Value can be of any type while the key is
       limited to alphanumeric, dashes ("-") and underscore ("-") characters.
get    load a value from the secret store. This command requires 1 additionnal
       argument: [KEY].
delete remove a key from the secret store. This command requires 1 additional
       argument: [KEY].
list   Display all keys stored in the secret store.

The global flags are:`)
	fmt.Fprint(os.Stderr, "\n\n")
	flag.PrintDefaults()
	os.Exit(1)
}

// version
const (
	major = "1"
	minor = "0"
	patch = "0"
)

// printVersion prints the current version of the program and then exits.
func printVersion() {
	fmt.Printf("gosecret v%s.%s.%s\n", major, minor, patch)
	os.Exit(0)
}

// Command line flags.
var (
	version        = flag.Bool("version", false, "print version")
)

func main() {
	flag.Usage = usage
	flag.Parse()

	if *version {
		printVersion()
	}

	if flag.NArg() < 2 {
		log.Fatal("invalid number of argument")
	}

	fmt.Printf("Passphrase: ")
	passphrase, err := gopass.GetPasswd()
	if err != nil {
		log.Fatal("cannot read passphrase")
	}

	store, err := secret.OpenStore(flag.Arg(0), string(passphrase))
	if err != nil {
		log.Fatal("[error] ", err)
	}
	defer store.Close()

	switch cmd := flag.Arg(1); cmd {
	case "put":
		var key, value string
		switch flag.NArg() {
		case 3:
			log.Fatal("missing argument")
		case 4:
			key, value = flag.Arg(2), flag.Arg(3)
		default:
			log.Fatal("missing arguments")
		}
		if err := store.Put(key, []byte(value)); err != nil {
			log.Fatal("[error] ", err)
		}
		fmt.Println("data successfully added")
	case "get":
		if flag.NArg() != 3 {
			log.Fatal("missing key")
		}
		data, err := store.Get(flag.Arg(2))
		if err != nil {
			log.Fatal("[error] ", err)
		}
		fmt.Println("result: ", string(data))
	case "list":
		keys, err := store.Keys()
		if err != nil {
			log.Fatal("[error] ", err)
		}
		fmt.Println("Stored keys: ")
		for _, k := range keys {
			fmt.Println("\t-", k)
		}
	}
}
