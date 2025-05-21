package trinc

import (
	"crypto/ecdsa"

	"github.com/etclab/mu"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

const DefaultTPMDevPath = "/dev/tpmrm0"

type TPMType int

const (
	TPMTypeLinux     TPMType = iota //path string
	TPMTypeLinuxUDS                 // socketpath string
	TPMTypeSimulator                // needs nothing
)

type TrinketConfig struct {
	Type TPMType
	Path string // for Linux and LinuxUDS
}

type Trinket struct {
	TPM     transport.TPMCloser
	Key     *Key
	Counter *Counter
	NVPCR   *NVPCR
}

func NewTrinket(config *TrinketConfig, sk *ecdsa.PrivateKey) (*Trinket, error) {
	tk := new(Trinket)

	switch config.Type {
	case TPMTypeLinux:
		tpm, err := linuxtpm.Open(config.Path)
	case TPMTypeLinuxUDS:
		tpm, err := linuxudstpm.Open(config.Path)
	case TPMTypeSimulator:
		tpm, err := simulator.OpenSimulator()
	default:
		mu.BUG("invalid TMP type: %v", config.Type)
	}

	if err != nil {
		return nil, err
	}

	tk.TPM = tpm

	tk.Key, err = LoadECDSAPrivateKey(tk.TPM, sk)
	if err != nil {
		return nil, err
	}

	tk.Counter, err = NewCounter(tk.TPM)
	if err != nil {
		return nil, err
	}

	tk.NVPCR, err = NewNVPCR(tk.TPM)
	if err != nil {
		return nil, err
	}

	return tk, nil
}

func (tk *Trinket) Close() {
	if tk.Counter != nil {
		tk.Counter.Destroy()
		tk.Counter = nil
	}
	if tk.NVPCR != nil {
		tk.NVPCR.Destroy()
		tk.NVPCR = nil
	}

	if tk.Key != nil {
		tk.Key.Destroy()
		tk.Key = nil
	}

	if tk.TPM != nil {
		tk.TPM.Close()
		tk.TPM = nil
	}
}

func (tk *Trinket) AttestCounter(hash []byte) (*CounterAttestation, error) {
	err := tk.Counter.Increment()
	if err != nil {
		return nil, err
	}

	counterValue, err := tk.Counter.Read()
	if err != nil {
		return nil, err
	}

	digest := MakeCounterAttestationHash(counterValue, hash)

	// simulate NVCertify because our physical TPMs do not support it
	cmd := tpm2.Sign{
		KeyHandle: tpm2.NamedHandle{
			Handle: tk.Key.Handle,
			Name:   tk.Key.Name,
		},
		Digest: tpm2.TPM2BDigest{
			Buffer: digest,
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}

	resp, err := cmd.Execute(tk.TPM)
	if err != nil {
		return nil, err
	}

	tpmSig, err := resp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, err
	}

	sig := NewECDSASignature(tpmSig.SignatureR.Buffer, tpmSig.SignatureS.Buffer)

	attestation := &CounterAttestation{
		Counter:   counterValue,
		MsgHash:   hash,
		Signature: sig,
	}

	return attestation, nil
}

func (tk *Trinket) ExtendNVPCR(hash []byte) error {
	return tk.NVPCR.Extend(hash)
}

func (tk *Trinket) AttestNVPCR() (*NVPCRAttestation, error) {
	val, err := tk.NVPCR.Read()
	if err != nil {
		return nil, err
	}

	// simulate NVCertify because our physical TPMs do not support it
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

	resp, err := cmd.Execute(tk.TPM)
	if err != nil {
		return nil, err
	}

	tpmSig, err := resp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, err
	}

	sig := NewECDSASignature(tpmSig.SignatureR.Buffer, tpmSig.SignatureS.Buffer)

	attestation := &NVPCRAttestation{
		NVPCR:     val,
		Signature: sig,
	}

	return attestation, nil
}
