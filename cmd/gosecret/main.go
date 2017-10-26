package main

import (
	"flag"
	"fmt"
	"log"

	"e-xpert_solutions/go-secret/secret"

	"github.com/howeyc/gopass"
)

func main() {
	flag.Parse()

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
