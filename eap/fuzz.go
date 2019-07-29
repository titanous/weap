// +build gofuzz

package eap

import (
	"bytes"
	"encoding/binary"
)

func Fuzz(data []byte) int {
	packet, err := DecodePacket(data)
	if err != nil {
		return 0
	}
	encoded := packet.Encode(nil)
	if !bytes.Equal(encoded, data[:int(binary.BigEndian.Uint16(data[2:]))]) {
		panic("encode mismatch")
	}
	return 0
}
