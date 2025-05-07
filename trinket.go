package trinc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

const DefaultTPMDevPath = "/dev/tpm0"

type Trinket struct {
	TPM     transport.TPMCloser
	Key     *Key
	Counter *Counter
	NVPCR   *NVPCR
}

func NewTrinket(tpmPath string, sk *ecdsa.PrivateKey) (*Trinket, error) {
	tk := new(Trinket)
	tpm, err := linuxtpm.Open(tpmPath)
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

	var b bytes.Buffer
	b.Write(Uint64ToBinary(counterValue))
	b.Write(hash)
	digest := sha256.Sum256(b.Bytes())

	// simulate NVCertify because our physical TPMs do not support it
	cmd := tpm2.Sign{
		KeyHandle: tpm2.NamedHandle{
			Handle: tk.Key.Handle,
			Name:   tk.Key.Name,
		},
		Digest: tpm2.TPM2BDigest{
			Buffer: digest[:],
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

func (tk *Trinket) AttestNVPCR(hash []byte) (*NVPCRAttestation, error) {
	err := tk.NVPCR.Extend(hash)
	if err != nil {
		return nil, err
	}

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
