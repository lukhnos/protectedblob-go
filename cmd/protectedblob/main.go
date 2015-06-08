package main // import "lukhnos.org/protectedblob/cmd/protectedblob"

import (
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"log"
	"lukhnos.org/protectedblob"
	"os"
)

func readPassphrase(prompt string) (string, error) {
	oldState, err := terminal.MakeRaw(0)
	if err != nil {
		return "", err
	}
	defer terminal.Restore(0, oldState)

	term := terminal.NewTerminal(os.Stdin, "")
	passphrase, err := term.ReadPassword(prompt)
	if err != nil {
		return "", err
	}
	return passphrase, nil
}

func readEncryptionPassphrase(prompt1 string, prompt2 string) (string, error) {
	passphrase1, err := readPassphrase(prompt1)
	if err != nil {
		return "", err
	}

	passphrase2, err := readPassphrase(prompt2)
	if err != nil {
		return "", err
	}

	if passphrase1 != passphrase2 {
		return "", errors.New("Passphrase mismatch")
	}

	return passphrase1, nil
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("protectedblob: ")

	decrypt := flag.Bool("d", false, "Decrypt")
	changePassphase := flag.Bool("change-passphrase", false, "Change passphrase")
	rounds := flag.Int("r", 0, fmt.Sprintf("Rounds; if not set or set to 0, %v will be used when creating", protectedblob.DefaultRounds))
	output := flag.String("o", "", "Output file, default to stdout")

	flag.Parse()
	if len(flag.Args()) != 1 {
		fmt.Println("Usage: protectedblob [options] file")
		fmt.Println("Options:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	srcFilename := flag.Arg(0)
	src, err := ioutil.ReadFile(srcFilename)
	if err != nil {
		log.Fatal(err)
	}

	if *changePassphase && *decrypt {
		log.Fatal("The two flags are mutally exclusive")
	}

	if *changePassphase {
		fileInfo, err := os.Stat(srcFilename)
		if err != nil {
			log.Fatal(err)
		}

		envelope, err := protectedblob.FromJSON(src)
		if err != nil {
			log.Fatal(err)
		}

		oldPassphrase, err := readPassphrase("Old passphrase: ")
		if err != nil {
			log.Fatal(err)
		}

		newPassphrase, err := readEncryptionPassphrase("New passphrase: ", "Confirm passphrase: ")
		if err != nil {
			log.Fatal(err)
		}

		if oldPassphrase == newPassphrase {
			log.Fatal("Passphrase not changed")
		}

		var kdfRounds = envelope.ProtectedKey.Rounds
		if *rounds > 0 {
			kdfRounds = int32(*rounds)
		}

		if err := envelope.ChangePassphraseAndRounds(oldPassphrase, newPassphrase, kdfRounds); err != nil {
			log.Fatal(err)
		}

		dst, err := envelope.ToJSON()
		if err != nil {
			log.Fatal(err)
		}

		if err := ioutil.WriteFile(srcFilename, dst, fileInfo.Mode()); err != nil {
			log.Fatal(err)
		}

		return
	}

	var dst []byte

	if *decrypt {
		envelope, err := protectedblob.FromJSON(src)
		if err != nil {
			log.Fatal(err)
		}

		passphrase, err := readPassphrase("Passphrase: ")
		if err != nil {
			log.Fatal(err)
		}

		dst, err = envelope.GetPlaintext(passphrase)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		passphrase, err := readEncryptionPassphrase("Passphrase: ", "Confirm passphrase: ")
		if err != nil {
			log.Fatal(err)
		}

		var kdfRounds = protectedblob.DefaultRounds
		if *rounds > 0 {
			kdfRounds = int32(*rounds)
		}
		envelope, err := protectedblob.Create(src, passphrase, kdfRounds)
		if err != nil {
			log.Fatal(err)
		}

		dst, err = envelope.ToJSON()
		if err != nil {
			log.Fatal(err)
		}
	}

	var dstFile = os.Stdout
	if *output != "" {
		dstFile, err = os.OpenFile(*output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			log.Fatal(err)
		}
	}

	written, err := dstFile.Write(dst)
	if err != nil {
		log.Fatal(err)
	}

	if written != len(dst) {
		log.Fatal("Incorrect number of bytes written")
	}

	if err := dstFile.Close(); err != nil {
		log.Fatal(err)
	}
}
