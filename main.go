package main

import (
	"flag"
	"log"
	"os"

	"github.com/fysac/orbicfg/cfg"
)

const openIssueMsg = `
Please open a bug report at https://github.com/Fysac/orbicfg/issues.
Include the exact command that failed, the error message, and the the model and firmware version of your device.`

func main() {
	l := log.New(os.Stderr, "", 0)

	decryptFile := flag.String("decrypt", "", "file to decrypt (requires: -out)")
	encryptFile := flag.String("encrypt", "", "file to encrypt (requires: -out, -magic)")
	raw := flag.Bool("raw", false, "decrypt the raw bytes to a Base64-encoded field")
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
		_, configBytes, metadata, err := cfg.Decrypt(b)
		if err != nil {
			l.Println("decrypt config:", err)
			l.Fatalln(openIssueMsg)
		}
		wrapperJSON, err := cfg.ToJSON(configBytes, metadata, *raw)
		if err != nil {
			l.Println("create json wrapper:", err)
			l.Fatalln(openIssueMsg)
		}

		if err := writeFileNoTrunc(*outputFile, wrapperJSON); err != nil {
			l.Fatal(err)
		}
	} else if *encryptFile != "" {
		if *outputFile == "" {
			l.Println("-encrypt needs an output file")
			flag.Usage()
			os.Exit(1)
		}

		wrapperJSON, err := os.ReadFile(*encryptFile)
		if err != nil {
			l.Fatal(err)
		}
		configBytes, metadata, err := cfg.FromJSON(wrapperJSON)
		if err != nil {
			l.Fatalln("parse json wrapper:", err)
		}
		encryptedConfig, err := cfg.Encrypt(configBytes, metadata)
		if err != nil {
			l.Println("encrypt config:", err)
			l.Fatalln(openIssueMsg)
		}

		if err := writeFileNoTrunc(*outputFile, encryptedConfig); err != nil {
			l.Fatal(err)
		}
	} else {
		flag.Usage()
		os.Exit(1)
	}
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
