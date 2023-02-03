package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"

	"github.com/fysac/orbicfg/cfg"
)

const openIssueMsg = "Please open an issue at https://github.com/Fysac/orbicfg/issues. Include the error message above and the model of your device"

func main() {
	l := log.New(os.Stderr, "", 0)

	decryptFile := flag.String("decrypt", "", "file to decrypt (requires: -out)")
	ignoreChecksum := flag.Bool("ignore-checksum", false, "decrypt without verifying checksum")
	encryptFile := flag.String("encrypt", "", "file to encrypt (requires: -out, -magic)")
	magicNumber := flag.String("magic", "", "magic number to use for encryption")
	raw := flag.Bool("raw", false, "operate on raw bytes instead of json (use with caution)")
	outputFile := flag.String("out", "", "output file for decryption or encryption")
	flag.Parse()

	if *decryptFile != "" {
		if *outputFile == "" {
			l.Println("-decrypt needs an output file")
			flag.Usage()
			os.Exit(1)
		}

		b, err := os.ReadFile(*decryptFile)
		if err != nil {
			l.Fatal(err)
		}

		header, decryptedConfig, err := cfg.Decrypt(b, *ignoreChecksum)
		if err != nil {
			l.Println("decrypt error:", err)
			if err.Error() == cfg.ErrorInvalidChecksum {
				l.Println("Try again with -ignore-checksum?")
			} else {
				l.Println(openIssueMsg)
			}
			os.Exit(1)
		}

		if !*raw {
			decryptedConfig, err = cfg.ToJSON(decryptedConfig)
			if err != nil {
				l.Println("config to json:", err)
				l.Fatalln(openIssueMsg)
			}
		}
		if err := writeFileNoTrunc(*outputFile, decryptedConfig); err != nil {
			l.Fatal(err)
		}

		fmt.Println("Decrypted to", getAbsPath(*outputFile))
		fmt.Printf("Magic number is: 0x%08x\nPass this value in -magic to re-encrypt the config\n", header.Magic)
	} else if *encryptFile != "" {
		if *outputFile == "" {
			l.Println("-encrypt needs an output file")
			flag.Usage()
			os.Exit(1)
		}
		if *magicNumber == "" {
			l.Println("-encrypt needs a magic number")
			flag.Usage()
			os.Exit(1)
		}

		decryptedConfig, err := os.ReadFile(*encryptFile)
		if err != nil {
			l.Fatal(err)
		}

		if !*raw {
			decryptedConfig, err = cfg.FromJSON(decryptedConfig)
			if err != nil {
				l.Fatalf("%v: %v\n", getAbsPath(*encryptFile), err)
			}
		}

		magic, err := strconv.ParseUint(*magicNumber, 0, 32)
		if err != nil {
			l.Fatal(err)
		}
		l.Printf("Using 0x%08x as magic\n", uint32(magic))

		encryptedConfig, err := cfg.Encrypt(decryptedConfig, uint32(magic))
		if err != nil {
			l.Fatalf("%v: %v\n", *encryptFile, err)
		}

		if err := writeFileNoTrunc(*outputFile, encryptedConfig); err != nil {
			l.Fatal(err)
		}
		fmt.Println("Wrote encrypted config to", getAbsPath(*outputFile))
	} else {
		flag.Usage()
		os.Exit(1)
	}
}

func getAbsPath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		panic(err)
	}
	return abs
}

func writeFileNoTrunc(name string, b []byte) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err != nil {
		return err
	}
	return f.Close()
}
