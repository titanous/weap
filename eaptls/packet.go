package eaptls

import (
	"encoding/binary"
	"errors"

	"github.com/titanous/weap/eap"
)

type PacketFlag byte

const (
	FlagLength PacketFlag = 1 << 7
	FlagMore   PacketFlag = 1 << 6
	FlagStart  PacketFlag = 1 << 5
)

type PacketHeader struct {
	Outer  eap.PacketHeader
	Flags  PacketFlag
	Length uint32
}

func (h *PacketHeader) Encode(buf []byte, dataLen int) []byte {
	h.Outer.Type = eap.TypeTLS
	buf = h.Outer.Encode(buf, dataLen+h.EncodedLen())
	buf = append(buf, byte(h.Flags))
	if h.Flags&FlagLength != 0 {
		buf = append(buf,
			byte(h.Length>>24),
			byte(h.Length>>16),
			byte(h.Length>>8),
			byte(h.Length),
		)
	}
	return buf
}

func (h *PacketHeader) EncodedLen() int {
	l := 1 // flag (1 byte)
	if h.Flags&FlagLength != 0 {
		l += 4 // (length 4 bytes)
	}
	return l
}

type Packet struct {
	PacketHeader
	Data []byte
}

func (p *Packet) Encode(buf []byte) []byte {
	buf = p.PacketHeader.Encode(buf, len(p.Data))
	return append(buf, p.Data...)
}

func DecodePacket(in *eap.Packet) (*Packet, error) {
	if in.Type != eap.TypeTLS {
		return nil, errors.New("eaptls: not a TLS packet")
	}
	if len(in.Data) < 1 {
		return nil, errors.New("eaptls: missing flags")
	}
	out := &Packet{
		PacketHeader: PacketHeader{
			Outer: in.PacketHeader,
			Flags: PacketFlag(in.Data[0]),
		},
		Data: in.Data[1:],
	}
	if out.Flags&FlagLength != 0 {
		if len(out.Data) < 4 {
			return nil, errors.New("eaptls: missing TLS length")
		}
		out.Length = binary.BigEndian.Uint32(in.Data)
		out.Data = out.Data[4:]
	}
	return out, nil
}
