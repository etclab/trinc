package trinc_test

import (
	"bytes"
	"crypto/sha256"
	"os"
	"testing"

	"github.com/etclab/trinc"
)

func hashFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(data)
	return hash[:], nil
}

func TestNewTrinket(t *testing.T) {
	skFile := "testdata/sk.key"

	sk, err := trinc.LoadECDSAPrivateKeyFromPEMFile(skFile)
	if err != nil {
		t.Fatalf("can't read private key file %q: %v", skFile, err)
	}

	tk, err := trinc.NewTrinket(trinc.DefaultTPMDevPath, sk)
	if err != nil {
		t.Fatalf("can't create trinket: %v", err)
	}
	tk.Close()
}

func TestAttestCounter(t *testing.T) {
	skFile := "testdata/sk.key"
	pkFile := "testdata/pk.key"
	msgFile := "testdata/alice.txt"

	hash, err := hashFile(msgFile)
	if err != nil {
		t.Fatalf("can't hash msg file %q: %v", msgFile, err)
	}

	sk, err := trinc.LoadECDSAPrivateKeyFromPEMFile(skFile)
	if err != nil {
		t.Fatalf("can't read private key file %q: %v", skFile, err)
	}

	pk, err := trinc.LoadECDSAPublicKeyFromPEMFile(pkFile)
	if err != nil {
		t.Fatalf("error: can't read public key file %q: %v", pkFile, err)
	}

	tk, err := trinc.NewTrinket(trinc.DefaultTPMDevPath, sk)
	if err != nil {
		t.Fatalf("can't create trinket: %v", err)
	}
	defer tk.Close()

	a, err := tk.AttestCounter(hash)
	if err != nil {
		t.Fatalf("error: can't generate counter attestation: %v", err)
	}

	result := a.Verify(pk)
	if !result {
		t.Fatalf("attestation has an invalid signature")
	}

	if !bytes.Equal(a.MsgHash, hash) {
		t.Fatalf("attestation MsgHash != expected hash")
	}
}
