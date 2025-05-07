package trinc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
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

func (a *CounterAttestation) String() string {
	return fmt.Sprintf("CounterAttestation{Counter: %d, MsgHash: %x, Signature: {R: %x S: %x}",
		a.Counter, a.MsgHash, a.Signature.R, a.Signature.S)
}

func VerifyCounterAttestation(pk *ecdsa.PublicKey, a *CounterAttestation) bool {
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

func VerifyNVPCRAttestation(pk *ecdsa.PublicKey, a *NVPCRAttestation) bool {
	// XXX: Note that this simply verifies that a.Signature is over a.NVPCR;
	// the caller would also need to sheck that a.NVCPR === expected
	return ecdsa.Verify(pk, a.NVPCR, a.Signature.R, a.Signature.S)
}
