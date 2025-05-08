package main

import (
	"bytes"
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

    -attestation ATTESTATION_FILE
        The file to write/read the attestation to/from
        Required: sign, verify

Examples:
    $ ./trinctool -cmd genkey -sk sk.pem -pk pk.pem
    $ sudo ./trinctool -cmd loadkey -sk sk.pem
`

type Options struct {
	cmd             string
	skFile          string
	pkFile          string
	msgFile         string
	attestationFile string
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
	flag.StringVar(&options.attestationFile, "attestation", "msg.attest", "")

	flag.Parse()

	return &options
}

func hashFile(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		mu.Fatalf("error: can't read file %q: %v", path, err)
	}
	hash := sha256.Sum256(data)
	return hash[:]
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

func doAttestCounter(skFile, msgFile, attestationFile string) {
	hash := hashFile(msgFile)

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

	err = attestation.ToFile(attestationFile)
	if err != nil {
		mu.Fatalf("error: can't write attestation to file %q: %v", attestationFile, err)
	}
}

func doAttestNVPCR(skFile, msgFile, attestationFile string) {
	hash := hashFile(msgFile)

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

	err = attestation.ToFile(attestationFile)
	if err != nil {
		mu.Fatalf("error: can't write attestation to file %q: %v", attestationFile, err)
	}
}

func doVerifyCounter(pkFile, msgFile, attestationFile string) {
	pk, err := trinc.LoadECDSAPublicKeyFromPEMFile(pkFile)
	if err != nil {
		mu.Fatalf("error: can't read public key file %q: %v", pkFile, err)
	}

	hash := hashFile(msgFile)

	a, err := trinc.LoadCounterAttestationFromFile(attestationFile)
	if err != nil {
		mu.Fatalf("error: can't read attestation file %q: %v", attestationFile, err)
	}
	fmt.Println(a)

	result := a.Verify(pk)
	if !result {
		fmt.Println("failure: attestation has an invalid signature")
		os.Exit(1)
	}

	if bytes.Equal(a.MsgHash, hash) {
		fmt.Println("failure: attestation MsgHash != expected hash")
		os.Exit(1)
	}

	fmt.Println("attestation verified successfully")
}

func doVerifyPCR(pkFile, nvpcrFile, attestationFile string) {
	pk, err := trinc.LoadECDSAPublicKeyFromPEMFile(pkFile)
	if err != nil {
		mu.Fatalf("error: can't read public key file %q: %v", pkFile, err)
	}

	expected, err := os.ReadFile(nvpcrFile)
	if err != nil {
		mu.Fatalf("error: can't read nvpcr file %q: %v", nvpcrFile, err)
	}

	a, err := trinc.LoadNVPCRAttestationFromFile(attestationFile)
	if err != nil {
		mu.Fatalf("error: can't read attestation file %q: %v", attestationFile, err)
	}
	fmt.Println(a)

	result := a.Verify(pk)
	if !result {
		fmt.Println("failure: attestation has an invalid signature")
		os.Exit(1)
	}

	if bytes.Equal(a.NVPCR, expected) {
		fmt.Println("failure: attestation NVPCR != expected hash")
		os.Exit(1)
	}

	fmt.Println("attestation verified successfully")
}

func main() {
	options := parseOptions()

	switch options.cmd {
	case "genkey":
		doGenKey(options.skFile, options.pkFile)
	case "attestctr":
		doAttestCounter(options.skFile, options.msgFile, options.attestationFile)
	case "attestpcr":
		doAttestNVPCR(options.skFile, options.msgFile, options.attestationFile)
	case "verifyctr":
		doVerifyCounter(options.pkFile, options.msgFile, options.attestationFile)
	case "verifypcr":
		doVerifyPCR(options.pkFile, options.msgFile, options.attestationFile)
	default:
		mu.Fatalf("unknown command: %q", options.cmd)
	}
}
