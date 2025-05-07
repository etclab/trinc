package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"flag"
	"fmt"
	"os"

	"github.com/etclab/mu"
	"github.com/etclab/trinc"
)

const usage = `trinctool [options]
    -cmd [genkey|attestctr|attestpcr]
    
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
	cmd     string
	skFile  string
	pkFile  string
	msgFile string
	sigFile string
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
	flag.StringVar(&options.msgFile, "msg", "msg.txt", "")
	flag.StringVar(&options.msgFile, "sig", "msg.sig", "")

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

func doAttestCounter(skFile, msgFile, sigFile string) {
	data, err := os.ReadFile(msgFile)
	if err != nil {
		mu.Fatalf("error: can't read message file %q: %v", msgFile, err)
	}
	hash := sha256.Sum256(data)

	sk, err := trinc.LoadECDSAPrivateKeyFromPEMFile(skFile)
	if err != nil {
		mu.Fatalf("error: can't load private key file %q: %v", skFile, err)
	}

	tk, err := trinc.NewTrinket(trinc.DefaultTPMDevPath, sk)
	if err != nil {
		mu.Fatalf("error: can't create trinket: %v", err)
	}
	defer tk.Close()

	attestation, err := tk.AttestCounter(hash[:])
	if err != nil {
		mu.Fatalf("error: can't generate attestation: %v", err)
	}
	fmt.Println(attestation)

	mu.UNUSED(sigFile)
}

func doAttestNVPCR(skFile, msgFile, sigFile string) {
	data, err := os.ReadFile(msgFile)
	if err != nil {
		mu.Fatalf("error: can't read message file %q: %v", msgFile, err)
	}
	hash := sha256.Sum256(data)

	sk, err := trinc.LoadECDSAPrivateKeyFromPEMFile(skFile)
	if err != nil {
		mu.Fatalf("error: can't load private key file %q: %v", skFile, err)
	}

	tk, err := trinc.NewTrinket(trinc.DefaultTPMDevPath, sk)
	if err != nil {
		mu.Fatalf("error: can't create trinket: %v", err)
	}
	defer tk.Close()

	attestation, err := tk.AttestNVPCR(hash[:])
	if err != nil {
		mu.Fatalf("error: can't generate attestation: %v", err)
	}
	fmt.Println(attestation)

	mu.UNUSED(sigFile)
}

func main() {
	options := parseOptions()

	// TODO: verify attestations
	switch options.cmd {
	case "genkey":
		doGenKey(options.skFile, options.pkFile)
	case "attestctr":
		doAttestCounter(options.skFile, options.msgFile, options.sigFile)
	case "attestpcr":
		doAttestNVPCR(options.skFile, options.msgFile, options.sigFile)
	default:
		mu.Fatalf("unknown command: %q", options.cmd)
	}
}
