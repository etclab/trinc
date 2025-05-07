package trinc

import (
	"testing"
)

func TestNewTrinket(t *testing.T) {
	keyFile := "testdata/sk.key"

	sk, err := LoadECDSAPrivateKeyFromPEMFile(keyFile)
	if err != nil {
		t.Fatalf("can't read private key file %q: %v", keyFile, err)
	}

	tr, err := NewTrinket(DefaultTPMDevPath, sk)
	if err != nil {
		t.Fatalf("can't create trinket: %v", err)
	}
	tr.Close()
}
