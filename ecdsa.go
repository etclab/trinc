package trinc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"os"

	"github.com/etclab/mu"
)

func MarshalECDSAPrivateKeyToPEM(sk *ecdsa.PrivateKey) ([]byte, error) {
	derData, err := x509.MarshalPKCS8PrivateKey(sk)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derData,
	}

	pemData := pem.EncodeToMemory(block)
	if pemData == nil {
		return nil, err
	}

	return pemData, nil
}

func StoreECDSAPrivateKeyToPEMFile(pk *ecdsa.PrivateKey, keyPath string) error {
	pemData, err := MarshalECDSAPrivateKeyToPEM(pk)
	if err != nil {
		return err
	}
	return os.WriteFile(keyPath, pemData, 0o644)
}

func UnmarshalECDSAPrivateKeyFromPEM(pemData []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("error: failed fo parse PEM block containing private key")
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	sk, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("error: file does not contain an ECDSA private key")
	}

	if sk.Curve != elliptic.P256() {
		return nil, errors.New("unsupported curve, expected P-256")
	}

	return sk, nil
}

func LoadECDSAPrivateKeyFromPEMFile(keyPath string) (*ecdsa.PrivateKey, error) {
	pemData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	return UnmarshalECDSAPrivateKeyFromPEM(pemData)
}

func MarshalECDSAPublicKeyToPEM(pk *ecdsa.PublicKey) ([]byte, error) {
	derData, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derData,
	}

	pemData := pem.EncodeToMemory(block)
	if pemData == nil {
		return nil, err
	}

	return pemData, nil
}

func StoreECDSAPublicKeyToPEMFile(pk *ecdsa.PublicKey, keyPath string) error {
	pemData, err := MarshalECDSAPublicKeyToPEM(pk)
	if err != nil {
		return err
	}
	return os.WriteFile(keyPath, pemData, 0o644)
}

func UnmarshalECDSAPublicKeyFromPEM(pemData []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("failed fo parse PEM block containing ECDSA public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pk, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("file does not contain an ECDSA public key")
	}

	return pk, nil
}

func LoadECDSAPublicKeyFromPEMFile(keyPath string) (*ecdsa.PublicKey, error) {
	pemData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	return UnmarshalECDSAPublicKeyFromPEM(pemData)
}

func GenerateECDSAKey() *ecdsa.PrivateKey {
	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		mu.Panicf("ecdsa.GenerateKey: %v", err)
	}
	return sk
}

type ECDSASignature struct {
	R, S *big.Int
}

func NewECDSASignature(r []byte, s []byte) *ECDSASignature {
	sig := new(ECDSASignature)
	sig.R = new(big.Int).SetBytes(r)
	sig.S = new(big.Int).SetBytes(s)
	return sig
}

func VerifyECDSA(pk *ecdsa.PublicKey, hash []byte, sig *ECDSASignature) bool {
	return ecdsa.Verify(pk, hash, sig.R, sig.S)
}
