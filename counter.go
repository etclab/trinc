package trinc

import (
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

type Counter struct {
	NVIndex tpm2.TPMIRHNVIndex
	NVName  tpm2.TPM2BName
	TPM     transport.TPMCloser
}

func NewCounter(thetpm transport.TPMCloser) (*Counter, error) {
	index := tpm2.TPMHandle(0x0180001F)

	public := tpm2.New2B(
		tpm2.TPMSNVPublic{
			NVIndex: index,
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

	nvDefineSpaceCmd := tpm2.NVDefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		Auth: tpm2.TPM2BAuth{
			//Buffer: []byte(password),
			Buffer: []byte{},
		},
		PublicInfo: public,
	}

	if _, err := nvDefineSpaceCmd.Execute(thetpm); err != nil {
		return nil, err
	}

	// Get the counter's name
	readPublicCmd := tpm2.NVReadPublic{
		NVIndex: index,
	}

	readPublicResp, err := readPublicCmd.Execute(thetpm)
	if err != nil {
		return nil, err
	}

	c := &Counter{
		NVIndex: index,
		NVName:  readPublicResp.NVName,
		TPM:     thetpm,
	}

	// the counter needs to be incremented once to initialize it (reads
	// of the counter fail until it is initialized)
	nvIncrementCmd := tpm2.NVIncrement{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth([]byte{})),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: c.NVIndex,
			Name:   c.NVName,
		},
	}

	_, err = nvIncrementCmd.Execute(thetpm)

	// The act of initializing the counter changes its name; retrieve
	// the new name.
	readPublicCmd = tpm2.NVReadPublic{
		NVIndex: c.NVIndex,
	}

	readPublicResp, err = readPublicCmd.Execute(thetpm)
	if err != nil {
		return nil, err
	}

	c.NVName = readPublicResp.NVName
	return c, nil
}

func (c *Counter) Destroy() error {
	cmd := tpm2.NVUndefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		NVIndex: tpm2.NamedHandle{
			Handle: c.NVIndex,
			Name:   c.NVName,
		},
	}

	_, err := cmd.Execute(c.TPM)
	return err
}

func (c *Counter) Read() (uint64, error) {
	cmd := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth([]byte{})),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: c.NVIndex,
			Name:   c.NVName,
		},
		Offset: 0,
		Size:   8,
	}

	resp, err := cmd.Execute(c.TPM)
	if err != nil {
		return 0, err
	}

	return BinaryToUint64(resp.Data.Buffer), nil
}

func (c *Counter) Increment() error {
	cmd := tpm2.NVIncrement{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth([]byte{})),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: c.NVIndex,
			Name:   c.NVName,
		},
	}

	_, err := cmd.Execute(c.TPM)
	return err
}
