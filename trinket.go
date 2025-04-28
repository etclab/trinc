package trinc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"os"

	"github.com/etclab/mu"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

const DefaultTPMDevPath = "/dev/tpm0"

type Trinket struct {
	TPM         transport.TPMCloser
	KeyIsLoaded bool
	KeyHandle   tpm2.TPMHandle
	KeyName     tpm2.TPM2BName
	Counter     *tpm2.NVDefineSpace
}

func NewTrinket(tpmPath string) *Trinket {
	tk := new(Trinket)
	tpm, err := linuxtpm.Open(tpmPath)
	if err != nil {
		mu.Fatalf("could not connect to TPM at %q: %v", tpmPath, err)
	}

	tk.TPM = tpm

	return tk
}

func (tk *Trinket) DestroyKey() {
	if !tk.KeyIsLoaded {
		return
	}

	cmd := tpm2.FlushContext{
		FlushHandle: tk.KeyHandle,
	}

	_, err := cmd.Execute(tk.TPM)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: flushing key failed: %v", err)
	} else {
		tk.KeyIsLoaded = false
	}
}

func (tk *Trinket) Close() {
	fmt.Println("Closing TPM...")
	tk.DestroyCounter()
	tk.DestroyKey()
	tk.TPM.Close()
}

func (tk *Trinket) LoadECDSAPrivateKey(sk *ecdsa.PrivateKey) error {
	sensitive := tpm2.New2B(
		tpm2.TPMTSensitive{
			SensitiveType: tpm2.TPMAlgECC,
			Sensitive: tpm2.NewTPMUSensitiveComposite(
				tpm2.TPMAlgECC,
				&tpm2.TPM2BECCParameter{
					Buffer: sk.D.FillBytes(make([]byte, 32)),
				},
			),
		})

	public := tpm2.New2B(
		tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				SignEncrypt:  true,
				UserWithAuth: true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCParms{
					CurveID: tpm2.TPMECCNistP256,
					Scheme: tpm2.TPMTECCScheme{
						Scheme: tpm2.TPMAlgECDSA,
						Details: tpm2.NewTPMUAsymScheme(
							tpm2.TPMAlgECDSA,
							&tpm2.TPMSSigSchemeECDSA{
								HashAlg: tpm2.TPMAlgSHA256,
							},
						),
					},
				},
			),
			Unique: tpm2.NewTPMUPublicID(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCPoint{
					X: tpm2.TPM2BECCParameter{
						Buffer: sk.X.FillBytes(make([]byte, 32)),
					},
					Y: tpm2.TPM2BECCParameter{
						Buffer: sk.Y.FillBytes(make([]byte, 32)),
					},
				},
			),
		})

	cmd := tpm2.LoadExternal{
		InPrivate: sensitive,
		InPublic:  public,
		// Hierarchy: TODO, // TPMIRHHierarchy
	}

	resp, err := cmd.Execute(tk.TPM)
	if err != nil {
		return err
	}

	tk.KeyHandle = resp.ObjectHandle
	tk.KeyName = resp.Name

	return nil
}

func (tk *Trinket) CounterPublicContents() *tpm2.TPMSNVPublic {
	pub, err := tk.Counter.PublicInfo.Contents()
	if err != nil {
		mu.Panicf("%v", err)
	}
	return pub
}

func (tk *Trinket) ReadPublic() *tpm2.NVReadPublicResponse {
	pub := tk.CounterPublicContents()
	cmd := tpm2.NVReadPublic{
		NVIndex: pub.NVIndex,
	}
	resp, err := cmd.Execute(tk.TPM)
	if err != nil {
		mu.Panicf("Calling TPM2_NV_ReadPublic: %v", err)
	}
	return resp
}

func (tk *Trinket) CreateCounter() {
	public := tpm2.New2B(
		tpm2.TPMSNVPublic{
			NVIndex: tpm2.TPMHandle(0x0180001F),
			NameAlg: tpm2.TPMAlgSHA256,
			Attributes: tpm2.TPMANV{
				OwnerWrite: true,
				OwnerRead:  true,
				AuthWrite:  true,
				AuthRead:   true,
				NT:         tpm2.TPMNTCounter,
				NoDA:       true,
			},
			DataSize: 8,
		})

	cmd := tpm2.NVDefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		Auth: tpm2.TPM2BAuth{
			//Buffer: []byte(password),
			Buffer: []byte{},
		},
		PublicInfo: public,
	}
	if _, err := cmd.Execute(tk.TPM); err != nil {
		fmt.Printf("Calling TPM2_NV_DefineSpace: %v\n", err)
	}

	tk.Counter = &cmd
}

func (tk *Trinket) DestroyCounter() {
	if tk.Counter == nil {
		return
	}

	pub := tk.CounterPublicContents()
	readPubResp := tk.ReadPublic()

	cmd := tpm2.NVUndefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		NVIndex: tpm2.NamedHandle{
			Handle: pub.NVIndex,
			Name:   readPubResp.NVName,
		},
	}

	_, err := cmd.Execute(tk.TPM)
	if err != nil {
		fmt.Printf("could not undefine NV index: %v\n", err)
		return
	}

	tk.Counter = nil
}

func (tk *Trinket) ReadCounter() uint64 {
	pub := tk.CounterPublicContents()
	readPubResp := tk.ReadPublic()

	fmt.Printf("read: nvName: %v\n", readPubResp.NVName)
	read := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth([]byte{})),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: pub.NVIndex,
			Name:   readPubResp.NVName,
		},
		Offset: 0,
		Size:   8,
	}

	resp, err := read.Execute(tk.TPM)
	if err != nil {
		mu.Panicf("Calling TPM2_NV_Read: %v", err)
	}

	return BinaryToUint64(resp.Data.Buffer)
}

func (tk *Trinket) IncrementCounter() {
	pub := tk.CounterPublicContents()
	readPubResp := tk.ReadPublic()

	incr := tpm2.NVIncrement{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth([]byte{})),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: pub.NVIndex,
			Name:   readPubResp.NVName,
		},
	}
	if _, err := incr.Execute(tk.TPM); err != nil {
		mu.Fatalf("error: TPM2_NV_Increment: %v", err)
	}
}

type Attestation struct {
	OldCounter uint64
	NewCounter uint64
	MsgHash    []byte
	Signature  *ECDSASignature
}

func (a *Attestation) String() string {
	return fmt.Sprintf("Attestation{OldCounter: %d, NewCounter: %d, MsgHash: %x, Signature: {R: %x S: %x}",
		a.OldCounter, a.NewCounter, a.MsgHash, a.Signature.R, a.Signature.S)
}

func (tk *Trinket) Attest(hash []byte) *Attestation {
	oldCounter := tk.ReadCounter()
	tk.IncrementCounter()
	newCounter := tk.ReadCounter()

	var b bytes.Buffer
	b.Write(Uint64ToBinary(oldCounter))
	b.Write(Uint64ToBinary(newCounter))
	b.Write(hash)
	digest := sha256.Sum256(b.Bytes())

	cmd := tpm2.Sign{
		KeyHandle: tpm2.NamedHandle{
			Handle: tk.KeyHandle,
			Name:   tk.KeyName,
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
		mu.Panicf("error: TPM2_Sign failed: %v", err)
	}

	tpmSig, err := resp.Signature.Signature.ECDSA()
	if err != nil {
		mu.Panicf("error: failed to parse TPM signature: %v", err)
	}

	sig := NewECDSASignature(tpmSig.SignatureR.Buffer, tpmSig.SignatureS.Buffer)

	return &Attestation{
		OldCounter: oldCounter,
		NewCounter: newCounter,
		MsgHash:    hash,
		Signature:  sig,
	}
}
