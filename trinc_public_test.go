package trinc_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/etclab/mu"
	"github.com/etclab/trinc"
	"github.com/google/go-tpm/tpm2"
)

const (
	ECDSAPrivateKeyFile = "testdata/sk.key"
	ECDSAPublicKeyFile  = "testdata/pk.key"
	MsgFile             = "testdata/alice.txt"
)

var Config trinc.Config

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

	tk, err := trinc.NewTrinket(&Config, sk)
	if err != nil {
		t.Fatalf("can't create trinket: %v", err)
	}

	return tk
}

func createTrinketB(b *testing.B) *trinc.Trinket {
	sk, err := trinc.LoadECDSAPrivateKeyFromPEMFile(ECDSAPrivateKeyFile)
	if err != nil {
		b.Fatalf("can't read private key file %q: %v", ECDSAPrivateKeyFile, err)
	}

	tk, err := trinc.NewTrinket(&Config, sk)
	if err != nil {
		b.Fatalf("can't create trinket: %v", err)
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

func BenchmarkAttestCounter(b *testing.B) {
	hash, err := hashFile(MsgFile)
	if err != nil {
		b.Fatalf("can't hash msg file %q: %v", MsgFile, err)
	}

	tk := createTrinketB(b)
	defer tk.Close()

	for b.Loop() {
		_, err := tk.AttestCounter(hash)
		if err != nil {
			b.Fatalf("error: can't generate counter attestation: %v", err)
		}
	}
}

func BenchmarkExtendNVPCR(b *testing.B) {
	hash, err := hashFile(MsgFile)
	if err != nil {
		b.Fatalf("can't hash msg file %q: %v", MsgFile, err)
	}

	tk := createTrinketB(b)
	defer tk.Close()

	for b.Loop() {
		err := tk.ExtendNVPCR(hash)
		if err != nil {
			b.Fatalf("error: can't extend nvpcr: %v", err)
		}
	}
}

func BenchmarkAttestNVPCR(b *testing.B) {
	tk := createTrinketB(b)
	defer tk.Close()

	for b.Loop() {
		_, err := tk.AttestNVPCR()
		if err != nil {
			b.Fatalf("error: can't generate nvpcr attestation: %v", err)
		}
	}
}

func BenchmarkExtendAndAttestNVPCR(b *testing.B) {
	hash, err := hashFile(MsgFile)
	if err != nil {
		b.Fatalf("can't hash msg file %q: %v", MsgFile, err)
	}

	tk := createTrinketB(b)
	defer tk.Close()

	for b.Loop() {
		err := tk.ExtendNVPCR(hash)
		if err != nil {
			b.Fatalf("error: can't extend nvpcr: %v", err)
		}

		_, err = tk.AttestNVPCR()
		if err != nil {
			b.Fatalf("error: can't generate nvpcr attestation: %v", err)
		}
	}
}

func BenchmarkSoftwareECDSASign(b *testing.B) {
	hash, err := hashFile(MsgFile)
	if err != nil {
		b.Fatalf("can't hash msg file %q: %v", MsgFile, err)
	}

	sk, err := trinc.LoadECDSAPrivateKeyFromPEMFile(ECDSAPrivateKeyFile)
	if err != nil {
		b.Fatalf("can't read private key file %q: %v", ECDSAPrivateKeyFile, err)
	}

	for b.Loop() {
		_, err := ecdsa.SignASN1(rand.Reader, sk, hash)
		if err != nil {
			b.Fatalf("error: can't generate software ECDSA signature: %v", err)
		}
	}
}

func BenchmarkHardwareECDSASign(b *testing.B) {
	tk := createTrinketB(b)
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

	for b.Loop() {
		_, err := cmd.Execute(tk.TPM)
		if err != nil {
			b.Fatalf("can't ECDSA-sign with TPM: %v", err)
		}
	}
}

func TestMain(m *testing.M) {
	var typeStr string

	flag.StringVar(&Config.Path, "path", trinc.DefaultTPMDevPath, "path to TPM device/socket")
	flag.StringVar(&typeStr, "type", "linux", "TPM type (linux|linuxuds|simulator")
	flag.Parse()

	switch strings.ToLower(typeStr) {
	case "linux":
		Config.Type = trinc.TPMTypeLinux
	case "linuxuds":
		Config.Type = trinc.TPMTypeLinuxUDS
	case "simulator":
		Config.Type = trinc.TPMTypeSimulator
	default:
		mu.Fatalf("bad option: unknown TPM type %q", typeStr)
	}

	status := m.Run()
	os.Exit(status)
}
