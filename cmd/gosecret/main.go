// Command gosecret is a tool to manage a secret key/value store.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/e-XpertSolutions/go-secret/secret"

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

func fatal(v ...interface{}) {
	fmt.Fprintln(os.Stderr, v...)
	os.Exit(1)
}

func fatalf(format string, v ...interface{}) {
	fmt.Fprintln(os.Stderr, fmt.Sprintf(format, v...))
	os.Exit(1)
}

// Command line flags.
var (
	version        = flag.Bool("version", false, "print version")
	passphraseFlag = flag.String("passphrase", "", "set the passphrase instead of asking it interactively")
)

func main() {
	flag.Usage = usage
	flag.Parse()

	if *version {
		printVersion()
	}

	if flag.NArg() < 2 {
		fatal(`Invalid number of argument:

	Gosecret requires at least the path to the secret store and a command to be
	executed.

Run 'gosecret --help' for usage.`)
	}

	var passphrase string
	if passphrase = *passphraseFlag; passphrase != "" {
		fmt.Printf("Passphrase: ")
		pswd, err := gopass.GetPasswd()
		if err != nil {
			fatal("Cannot read passphrase")
		}
		passphrase = string(pswd)
	}

	store, err := secret.OpenStore(flag.Arg(0), passphrase)
	if err != nil {
		fatal(err)
	}
	defer store.Close()

	switch cmd := flag.Arg(1); cmd {
	case "put":
		var key, value string
		switch flag.NArg() {
		case 3:
			fatal("Missing key and value arguments.\nRun 'gosecret --help' for usage.")
		case 4:
			key, value = flag.Arg(2), flag.Arg(3)
		default:
			fatal("'put' command expect key and value arguments.\nRun 'gosecret --help' for usage.")
		}
		if err := store.Put(key, []byte(value)); err != nil {
			fatal("error: ", err)
		}
		fmt.Println("Key/Value successfully stored.")
	case "get":
		if flag.NArg() != 3 {
			fatal("Missing key argument.\nRun 'gosecret --help' for usage.")
		}
		data, err := store.Get(flag.Arg(2))
		if err != nil {
			fatal(err)
		}
		fmt.Println("Value: ", string(data))
	case "list":
		keys, err := store.Keys()
		if err != nil {
			fatal("error: ", err)
		}
		fmt.Println("Stored keys: ")
		for _, k := range keys {
			fmt.Println("\t-", k)
		}
	default:
		fatalf("Unknown subcommand '%s'.\nRun 'gosecret --help' for usage.", cmd)
	}
}
