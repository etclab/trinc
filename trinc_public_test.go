package trinc_test

import (
	"testing"

	"github.com/etclab/trinc"
)

func TestNewTrinket(t *testing.T) {
	keyFile := "testdata/sk.key"

	sk, err := trinc.LoadECDSAPrivateKeyFromPEMFile(keyFile)
	if err != nil {
		t.Fatalf("can't read private key file %q: %v", keyFile, err)
	}

	tr, err := trinc.NewTrinket(trinc.DefaultTPMDevPath, sk)
	if err != nil {
		t.Fatalf("can't create trinket: %v", err)
	}
	tr.Close()
}
