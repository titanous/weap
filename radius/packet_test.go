package radius

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestDecodePacketAttributesZeroLength(t *testing.T) {
	_, err := DecodePacket([]byte("\x01=\x00<\x005\x00/\x00\n\xc0\a\xc0\x11\xc0\x02\xc0\f\x00\x05" +
		"\x00\x04\x01\x00\x00\x12\x00\n\x00\b\x00\x06\x00\x17\x00\x18\x00\x19\x00\v" +
		"\x00\x02\x01\x00\x18\x12f\xb1\xafbf(\xa2W/\x8e\xe1C\xe8#" +
		"\xa4\xa1P\x12=\xf8W\x99\xf8\x1dϓ\xfd[\x81\xf1q\xc5֧"))
	if err == nil {
		t.Error("expected attribute decode error, got nil")
	}
}

func TestDecodePacketZeroLengthAttributeData(t *testing.T) {
	_, err := DecodePacket([]byte("\v0\x00)00000000000000000\x010000000000000000000"))
	if err == nil {
		t.Error("expected attribute decode error, got nil")
	}
}

func TestDecodeEncodeRoundTrip(t *testing.T) {
	data := []byte("\v0\x00\x1400000000000000000")
	packet, err := DecodePacket(data)
	if err != nil {
		t.Error(err)
	}
	encoded := packet.Encode(nil)
	if !bytes.Equal(encoded, data[:int(binary.BigEndian.Uint16(data[2:]))]) {
		panic("encode mismatch")
	}
}
