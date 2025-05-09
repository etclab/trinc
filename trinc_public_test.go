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

func createTrinket(t *testing.T) *trinc.Trinket {
	skFile := "testdata/sk.key"

	sk, err := trinc.LoadECDSAPrivateKeyFromPEMFile(skFile)
	if err != nil {
		t.Fatalf("can't read private key file %q: %v", skFile, err)
	}

	tk, err := trinc.NewTrinket(trinc.DefaultTPMDevPath, sk)
	if err != nil {
		t.Fatalf("can't create trinket: %v", err)
	}

	return tk
}

func TestNewTrinket(t *testing.T) {
	tk := createTrinket(t)
	tk.Close()
}

func TestAttestCounter(t *testing.T) {
	pkFile := "testdata/pk.key"
	msgFile := "testdata/alice.txt"

	hash, err := hashFile(msgFile)
	if err != nil {
		t.Fatalf("can't hash msg file %q: %v", msgFile, err)
	}

	pk, err := trinc.LoadECDSAPublicKeyFromPEMFile(pkFile)
	if err != nil {
		t.Fatalf("error: can't read public key file %q: %v", pkFile, err)
	}

	tk := createTrinket(t)
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

func TestAttestNVPCR(t *testing.T) {
	pkFile := "testdata/pk.key"
	msgFile := "testdata/dorothy.txt"

	hash, err := hashFile(msgFile)
	if err != nil {
		t.Fatalf("can't hash msg file %q: %v", msgFile, err)
	}

	b := make([]byte, 32)
	b = append(b, hash[:]...)
	expected := sha256.Sum256(b)

	pk, err := trinc.LoadECDSAPublicKeyFromPEMFile(pkFile)
	if err != nil {
		t.Fatalf("error: can't read public key file %q: %v", pkFile, err)
	}

	tk := createTrinket(t)
	defer tk.Close()

	err = tk.ExtendNVPCR(hash)
	if err != nil {
		t.Fatalf("error: can't extend nvpcr: %v", err)
	}

	a, err := tk.AttestNVPCR()
	if err != nil {
		t.Fatalf("error: can't generate nvpcr attestation: %v", err)
	}

	result := a.Verify(pk)
	if !result {
		t.Fatalf("attestation has an invalid signature")
	}

	if !bytes.Equal(a.NVPCR, expected[:]) {
		t.Fatalf("attestation's NVPCR != expected hash")
	}
}

var blackholeCounter *trinc.CounterAttestation

func BenchmarkAttestCounter(b *testing.B) {
	msgFile := "testdata/alice.txt"
	skFile := "testdata/sk.key"

	hash, err := hashFile(msgFile)
	if err != nil {
		b.Fatalf("can't hash msg file %q: %v", msgFile, err)
	}

	sk, err := trinc.LoadECDSAPrivateKeyFromPEMFile(skFile)
	if err != nil {
		b.Fatalf("can't read private key file %q: %v", skFile, err)
	}

	tk, err := trinc.NewTrinket(trinc.DefaultTPMDevPath, sk)
	if err != nil {
		b.Fatalf("can't create trinket: %v", err)
	}
	defer tk.Close()

	for i := 0; i < b.N; i++ {
		a, err := tk.AttestCounter(hash)
		if err != nil {
			b.Fatalf("error: can't generate counter attestation: %v", err)
		}
		// ensure compiler does not optimize away call to tk.AttestCounter()
		blackholeCounter = a
	}
}

func BenchmarkExtendNVPCR(b *testing.B) {
	msgFile := "testdata/alice.txt"
	skFile := "testdata/sk.key"

	hash, err := hashFile(msgFile)
	if err != nil {
		b.Fatalf("can't hash msg file %q: %v", msgFile, err)
	}

	sk, err := trinc.LoadECDSAPrivateKeyFromPEMFile(skFile)
	if err != nil {
		b.Fatalf("can't read private key file %q: %v", skFile, err)
	}

	tk, err := trinc.NewTrinket(trinc.DefaultTPMDevPath, sk)
	if err != nil {
		b.Fatalf("can't create trinket: %v", err)
	}
	defer tk.Close()

	for i := 0; i < b.N; i++ {
		err := tk.ExtendNVPCR(hash)
		if err != nil {
			b.Fatalf("error: can't extend nvpcr: %v", err)
		}
	}
}

var blackholeNVPCR *trinc.NVPCRAttestation

func BenchmarkAttestNVPCR(b *testing.B) {
	skFile := "testdata/sk.key"

	sk, err := trinc.LoadECDSAPrivateKeyFromPEMFile(skFile)
	if err != nil {
		b.Fatalf("can't read private key file %q: %v", skFile, err)
	}

	tk, err := trinc.NewTrinket(trinc.DefaultTPMDevPath, sk)
	if err != nil {
		b.Fatalf("can't create trinket: %v", err)
	}
	defer tk.Close()

	for i := 0; i < b.N; i++ {
		a, err := tk.AttestNVPCR()
		if err != nil {
			b.Fatalf("error: can't generate nvpcr attestation: %v", err)
		}
		// ensure compiler does not optimize away call to tk.AttestNVPCR()
		blackholeNVPCR = a
	}
}

func BenchmarkExtendAndAttestNVPCR(b *testing.B) {
	msgFile := "testdata/alice.txt"
	skFile := "testdata/sk.key"

	hash, err := hashFile(msgFile)
	if err != nil {
		b.Fatalf("can't hash msg file %q: %v", msgFile, err)
	}

	sk, err := trinc.LoadECDSAPrivateKeyFromPEMFile(skFile)
	if err != nil {
		b.Fatalf("can't read private key file %q: %v", skFile, err)
	}

	tk, err := trinc.NewTrinket(trinc.DefaultTPMDevPath, sk)
	if err != nil {
		b.Fatalf("can't create trinket: %v", err)
	}
	defer tk.Close()

	for i := 0; i < b.N; i++ {
		err := tk.ExtendNVPCR(hash)
		if err != nil {
			b.Fatalf("error: can't extend nvpcr: %v", err)
		}

		a, err := tk.AttestNVPCR()
		if err != nil {
			b.Fatalf("error: can't generate nvpcr attestation: %v", err)
		}
		// ensure compiler does not optimize away call to tk.AttestNVPCR()
		blackholeNVPCR = a
	}
}
