package main

import (
	"crypto/ecdsa"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/etclab/mu"
	"github.com/etclab/trinc"
)

const usage = `ecdsatool [options]
    -cmd [genkey|loadkey]
    
    -sk SECRET_KEY_FILE
        The file with the secret ECDSA key.
		The file should be PEM-encoded

    -pk PUBLIC_KEY_FILE
        The file with the public ECDSA key (or to write the public key to)
        Required: keygen, verify

    -msg MESSAGE_FILE
        The file to sign
        Required: sign, verify

    -sig SIGNATURE_FILE
        The file to write/read the signature to/from
        Required: sign, verify

Examples:
    $ ./trinctool -cmd genkey -sk sk.pem -pk pk.pem
    $ sudo ./trinctool -cmd loadkey -sk sk.pem
`

type Options struct {
	cmd    string
	skFile string
	pkFile string
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "%s", usage)
}

func parseOptions() *Options {
	options := Options{}

	flag.Usage = printUsage
	flag.StringVar(&options.cmd, "cmd", "genkey", "")
	flag.StringVar(&options.skFile, "sk", "sk.key", "")
	flag.StringVar(&options.pkFile, "pk", "pk.key", "")

	flag.Parse()

	return &options
}

func doGenKey(skFile, pkFile string) {
	sk := trinc.GenerateECDSAKey()

	err := trinc.StoreECDSAPrivateKeyToPEMFile(sk, skFile)
	if err != nil {
		mu.Fatalf("error: can't write private key file %q: %v", skFile, err)
	}

	tmp := sk.Public() // pk is of type crypto.PublicKey
	pk := tmp.(*ecdsa.PublicKey)
	err = trinc.StoreECDSAPublicKeyToPEMFile(pk, pkFile)
	if err != nil {
		mu.Fatalf("error: can't write public key file %q: %v", pkFile, err)
	}
}

func doLoadKey(skFile string) {
	sk, err := trinc.LoadECDSAPrivateKeyFromPEMFile(skFile)
	if err != nil {
		mu.Fatalf("error: can't load private key file %q: %v", skFile, err)
	}

	tk := trinc.NewTrinket(trinc.DefaultTPMDevPath)
	defer tk.Close()

	err = tk.LoadECDSAPrivateKey(sk)
	if err != nil {
		mu.Fatalf("error: can't load private key file into tpm %v", err)
	}

	log.Printf("loaded private key: KeyHandle=%v KeyName=%v", tk.KeyHandle, tk.KeyName)
}

func main() {
	options := parseOptions()

	switch options.cmd {
	case "genkey":
		doGenKey(options.skFile, options.pkFile)
	case "loadkey":
		doLoadKey(options.skFile)
	default:
		mu.Fatalf("unknown command: %q", options.cmd)
	}
}
