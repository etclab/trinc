package trinc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
)

func MakeCounterAttestationHash(counter uint64, msgHash []byte) []byte {
	var b bytes.Buffer
	b.Write(Uint64ToBinary(counter))
	b.Write(msgHash)
	digest := sha256.Sum256(b.Bytes())
	return digest[:]
}

type CounterAttestation struct {
	Counter   uint64
	MsgHash   []byte
	Signature *ECDSASignature // signature is over the MsgHash and the Counter
}

func LoadCounterAttestationFromFile(path string) (*CounterAttestation, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var a CounterAttestation
	err = json.Unmarshal(b, &a)
	if err != nil {
		return nil, err
	}

	return &a, nil
}

func (a *CounterAttestation) ToFile(path string) error {
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func (a *CounterAttestation) String() string {
	return fmt.Sprintf("CounterAttestation{Counter: %d, MsgHash: %x, Signature: {R: %x S: %x}",
		a.Counter, a.MsgHash, a.Signature.R, a.Signature.S)
}

func (a *CounterAttestation) Verify(pk *ecdsa.PublicKey) bool {
	// XXX: Note that this simply verifies that a.Signature is over
	// a.Counter || a.MsgHash; the caller would also need to check that
	// a.MsgHash == expectedMsgHash and a.Counter == expectedCounter
	expectedHash := MakeCounterAttestationHash(a.Counter, a.MsgHash)
	return ecdsa.Verify(pk, expectedHash, a.Signature.R, a.Signature.S)
}

type NVPCRAttestation struct {
	NVPCR     []byte
	Signature *ECDSASignature // Signature is over the NVPCR value
}

func (a *NVPCRAttestation) String() string {
	return fmt.Sprintf("NVPCRAttestation{NVPCR: %x, Signature: {R: %x S: %x}",
		a.NVPCR, a.Signature.R, a.Signature.S)
}

func LoadNVPCRAttestationFromFile(path string) (*NVPCRAttestation, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var a NVPCRAttestation
	err = json.Unmarshal(b, &a)
	if err != nil {
		return nil, err
	}

	return &a, nil
}

func (a *NVPCRAttestation) ToFile(path string) error {
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func (a *NVPCRAttestation) Verify(pk *ecdsa.PublicKey) bool {
	// XXX: Note that this simply verifies that a.Signature is over a.NVPCR;
	// the caller would also need to sheck that a.NVCPR === expected
	return ecdsa.Verify(pk, a.NVPCR, a.Signature.R, a.Signature.S)
}
