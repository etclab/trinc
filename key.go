package trinc

import (
	"crypto/ecdsa"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

type Key struct {
	Handle tpm2.TPMHandle
	Name   tpm2.TPM2BName
	TPM    transport.TPMCloser
}

func LoadECDSAPrivateKey(thetpm transport.TPMCloser, sk *ecdsa.PrivateKey) (*Key, error) {
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
				//Restricted:   true,
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
		//Hierarchy: tpm2.TPMRHNull,
		//Hierarchy: TODO, // TPMIRHHierarchy
	}

	resp, err := cmd.Execute(thetpm)
	if err != nil {
		return nil, err
	}

	key := &Key{
		Handle: resp.ObjectHandle,
		Name:   resp.Name,
		TPM:    thetpm,
	}

	return key, nil
}

func (k *Key) Destroy() error {
	cmd := tpm2.FlushContext{
		FlushHandle: k.Handle,
	}
	_, err := cmd.Execute(k.TPM)
	return err
}
