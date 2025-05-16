package trinc_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"testing"

	"github.com/etclab/trinc"
	"github.com/google/go-tpm/tpm2"
)

const (
	ECDSAPrivateKeyFile = "testdata/sk.key"
	ECDSAPublicKeyFile  = "testdata/pk.key"
	MsgFile             = "testdata/alice.txt"
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
	sk, err := trinc.LoadECDSAPrivateKeyFromPEMFile(ECDSAPrivateKeyFile)
	if err != nil {
		t.Fatalf("can't read private key file %q: %v", ECDSAPrivateKeyFile, err)
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
	hash, err := hashFile(MsgFile)
	if err != nil {
		t.Fatalf("can't hash msg file %q: %v", MsgFile, err)
	}

	pk, err := trinc.LoadECDSAPublicKeyFromPEMFile(ECDSAPublicKeyFile)
	if err != nil {
		t.Fatalf("error: can't read public key file %q: %v", ECDSAPublicKeyFile, err)
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
	hash, err := hashFile(MsgFile)
	if err != nil {
		t.Fatalf("can't hash msg file %q: %v", MsgFile, err)
	}

	b := make([]byte, 32)
	b = append(b, hash[:]...)
	expected := sha256.Sum256(b)

	pk, err := trinc.LoadECDSAPublicKeyFromPEMFile(ECDSAPublicKeyFile)
	if err != nil {
		t.Fatalf("error: can't read public key file %q: %v", ECDSAPublicKeyFile, err)
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
	hash, err := hashFile(MsgFile)
	if err != nil {
		b.Fatalf("can't hash msg file %q: %v", MsgFile, err)
	}

	sk, err := trinc.LoadECDSAPrivateKeyFromPEMFile(ECDSAPrivateKeyFile)
	if err != nil {
		b.Fatalf("can't read private key file %q: %v", ECDSAPrivateKeyFile, err)
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
	hash, err := hashFile(MsgFile)
	if err != nil {
		b.Fatalf("can't hash msg file %q: %v", MsgFile, err)
	}

	sk, err := trinc.LoadECDSAPrivateKeyFromPEMFile(ECDSAPrivateKeyFile)
	if err != nil {
		b.Fatalf("can't read private key file %q: %v", ECDSAPrivateKeyFile, err)
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
	sk, err := trinc.LoadECDSAPrivateKeyFromPEMFile(ECDSAPrivateKeyFile)
	if err != nil {
		b.Fatalf("can't read private key file %q: %v", ECDSAPrivateKeyFile, err)
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
	hash, err := hashFile(MsgFile)
	if err != nil {
		b.Fatalf("can't hash msg file %q: %v", MsgFile, err)
	}

	sk, err := trinc.LoadECDSAPrivateKeyFromPEMFile(ECDSAPrivateKeyFile)
	if err != nil {
		b.Fatalf("can't read private key file %q: %v", ECDSAPrivateKeyFile, err)
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

var blackholeSig []byte

func BenchmarkSoftwareECDSASign(b *testing.B) {
	hash, err := hashFile(MsgFile)
	if err != nil {
		b.Fatalf("can't hash msg file %q: %v", MsgFile, err)
	}

	sk, err := trinc.LoadECDSAPrivateKeyFromPEMFile(ECDSAPrivateKeyFile)
	if err != nil {
		b.Fatalf("can't read private key file %q: %v", ECDSAPrivateKeyFile, err)
	}

	for i := 0; i < b.N; i++ {
		sig, err := ecdsa.SignASN1(rand.Reader, sk, hash)
		if err != nil {
			b.Fatalf("error: can't generate software ECDSA signature: %v", err)
		}
		// ensure compiler does not optimize away call to ecdsa.SignASN1
		blackholeSig = sig
	}
}

var blackholeSignResp *tpm2.SignResponse

func BenchmarkHardwareECDSASign(b *testing.B) {
	sk, err := trinc.LoadECDSAPrivateKeyFromPEMFile(ECDSAPrivateKeyFile)
	if err != nil {
		b.Fatalf("can't read private key file %q: %v", ECDSAPrivateKeyFile, err)
	}

	tk, err := trinc.NewTrinket(trinc.DefaultTPMDevPath, sk)
	if err != nil {
		b.Fatalf("can't create trinket: %v", err)
	}
	defer tk.Close()

	val, err := tk.NVPCR.Read()
	if err != nil {
		b.Fatalf("can't read NVPCR: %v", err)
	}

	cmd := tpm2.Sign{
		KeyHandle: tpm2.NamedHandle{
			Handle: tk.Key.Handle,
			Name:   tk.Key.Name,
		},
		Digest: tpm2.TPM2BDigest{
			Buffer: val[:],
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}

	for i := 0; i < b.N; i++ {
		resp, err := cmd.Execute(tk.TPM)
		if err != nil {
			b.Fatalf("can't ECDSA-sign with TPM: %v", err)
		}
		// ensure compiler does not optimize away call to cmd.Execute()
		blackholeSignResp = resp
	}
}
