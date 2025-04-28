package trinc

import (
	"encoding/binary"

	"github.com/etclab/mu"
)

func Uint64ToBinary(x uint64) []byte {
	buf := make([]byte, 8)
	_, err := binary.Encode(buf, binary.BigEndian, x)
	if err != nil {
		mu.Panicf("failed to convert uint64 to binary: %v", err)
	}
	return buf
}

func BinaryToUint64(buf []byte) uint64 {
	var val uint64
	_, err := binary.Decode(buf, binary.BigEndian, &val)
	if err != nil {
		mu.Panicf("failed to convert binary to uint64: %v", err)
	}
	return val
}
