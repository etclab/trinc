package trinc

import (
	"bytes"
	"crypto/sha256"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

type NVPCR struct {
	NVIndex tpm2.TPMIRHNVIndex
	NVName  tpm2.TPM2BName
	TPM     transport.TPMCloser
}

func NewNVPCR(thetpm transport.TPMCloser) (*NVPCR, error) {
	index := tpm2.TPMHandle(0x0180002F)

	public := tpm2.New2B(
		tpm2.TPMSNVPublic{
			NVIndex: index,
			NameAlg: tpm2.TPMAlgSHA256,
			Attributes: tpm2.TPMANV{
				OwnerWrite: true,
				OwnerRead:  true,
				AuthWrite:  true,
				AuthRead:   true,
				NT:         tpm2.TPMNTOrdinary,
				NoDA:       true,
			},
			DataSize: 32,
		})

	cmd := tpm2.NVDefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		Auth: tpm2.TPM2BAuth{
			//Buffer: []byte(password),
			Buffer: []byte{},
		},
		PublicInfo: public,
	}

	_, err := cmd.Execute(thetpm)
	if err != nil {
		return nil, err
	}

	// Get the nvpcr's name
	readPublicCmd := tpm2.NVReadPublic{
		NVIndex: index,
	}

	readPublicResp, err := readPublicCmd.Execute(thetpm)
	if err != nil {
		return nil, err
	}

	p := &NVPCR{
		NVIndex: index,
		NVName:  readPublicResp.NVName,
		TPM:     thetpm,
	}

	// the nvpcr needs to be initialized (reads fail until it is initialized)
	zeros := make([]byte, 32)
	err = p.Write(zeros)
	if err != nil {
		return nil, err
	}

	// The act of initializing the counter changes its name; retrieve
	// the new name.
	readPublicCmd = tpm2.NVReadPublic{
		NVIndex: p.NVIndex,
	}

	readPublicResp, err = readPublicCmd.Execute(thetpm)
	if err != nil {
		return nil, err
	}

	p.NVName = readPublicResp.NVName
	return p, nil

}

func (p *NVPCR) Destroy() error {
	cmd := tpm2.NVUndefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		NVIndex: tpm2.NamedHandle{
			Handle: p.NVIndex,
			Name:   p.NVName,
		},
	}

	_, err := cmd.Execute(p.TPM)
	return err
}

func (p *NVPCR) Read() ([]byte, error) {
	cmd := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth([]byte{})),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: p.NVIndex,
			Name:   p.NVName,
		},
		Offset: 0,
		Size:   32,
	}

	resp, err := cmd.Execute(p.TPM)
	if err != nil {
		return nil, err
	}

	return resp.Data.Buffer, nil
}

func (p *NVPCR) Write(data []byte) error {
	cmd := tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth([]byte{})),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: p.NVIndex,
			Name:   p.NVName,
		},
		Data: tpm2.TPM2BMaxNVBuffer{
			Buffer: data,
		},
		Offset: 0,
	}

	_, err := cmd.Execute(p.TPM)
	return err
}

func (p *NVPCR) Extend(hash []byte) error {
	// simulate NVExtend because go-tpm does not support it
	val, err := p.Read()
	if err != nil {
		return err
	}

	var b bytes.Buffer
	b.Write(val)
	b.Write(hash)
	digest := sha256.Sum256(b.Bytes())

	return p.Write(digest[:])
}
