package trinc

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/etclab/mu"
)

type CounterAttestation struct {
	Counter   uint64
	MsgHash   []byte
	Signature *ECDSASignature
}

func (a *CounterAttestation) String() string {
	return fmt.Sprintf("CounterAttestation{Counter: %d, MsgHash: %x, Signature: {R: %x S: %x}",
		a.Counter, a.MsgHash, a.Signature.R, a.Signature.S)
}

func VerifyCounterAttestation(a *CounterAttestation, pk *ecdsa.PublicKey) bool {
	// TODO: implement
	mu.UNUSED(a)
	mu.UNUSED(pk)
	return false
}

type NVPCRAttestation struct {
	NVPCR     []byte
	Signature *ECDSASignature
}

func (a *NVPCRAttestation) String() string {
	return fmt.Sprintf("NVPCRAttestation{NVPCR: %x, Signature: {R: %x S: %x}",
		a.NVPCR, a.Signature.R, a.Signature.S)
}

func VerifyNVPCRAttestation(a *NVPCRAttestation, pk *ecdsa.PublicKey) bool {
	// TODO: implement
	mu.UNUSED(a)
	mu.UNUSED(pk)
	return false
}
