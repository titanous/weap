package eap

import (
	"encoding/binary"
	"errors"
	"fmt"
)

//go:generate stringer -type=PacketCode,PacketType -output gen_string.go

type PacketCode byte

const (
	CodeRequest  PacketCode = 1
	CodeResponse PacketCode = 2
	CodeSuccess  PacketCode = 3
	CodeFailure  PacketCode = 4
)

type PacketType byte

const (
	TypeIdentity PacketType = 1
	TypeTLS      PacketType = 13
)

type PacketHeader struct {
	Code       PacketCode
	Type       PacketType
	Identifier byte
}

func (h *PacketHeader) Encode(buf []byte, dataLen int) []byte {
	length := uint16(h.EncodedLen() + dataLen)

	buf = append(buf, byte(h.Code))
	buf = append(buf, h.Identifier)
	buf = append(buf, byte(length>>8), byte(length))
	if h.HasType() {
		buf = append(buf, byte(h.Type))
	}

	return buf
}

func (h *PacketHeader) EncodedLen() int {
	l := 4 // code (1 byte) + identifier (1 byte) + length (2 bytes)
	if h.HasType() {
		l += 1 // type (1 byte)
	}
	return l
}

func (h *PacketHeader) HasType() bool {
	return h.Code == CodeRequest || h.Code == CodeResponse
}

type Packet struct {
	PacketHeader
	Data []byte
}

func (p *Packet) Encode(buf []byte) []byte {
	buf = p.PacketHeader.Encode(buf, len(p.Data))
	return append(buf, p.Data...)
}

func (p *Packet) EncodedLen() int {
	return p.PacketHeader.EncodedLen() + len(p.Data)
}

func (p *Packet) Response(code PacketCode) *Packet {
	res := &Packet{}
	res.Identifier = p.Identifier
	res.Code = code
	if code != CodeSuccess && code != CodeResponse {
		res.Type = p.Type
	}
	return p
}

func DecodePacket(data []byte) (*Packet, error) {
	if len(data) < 4 {
		return nil, errors.New("eap: packet is too short")
	}

	p := &Packet{}
	p.Code = PacketCode(data[0])

	if p.Code != CodeRequest && p.Code != CodeResponse && p.Code != CodeSuccess && p.Code != CodeFailure {
		return nil, fmt.Errorf("eap: unknown packet code %d", p.Code)
	}

	p.Identifier = data[1]

	length := binary.BigEndian.Uint16(data[2:])
	if length < 4 {
		return nil, fmt.Errorf("eap: invalid packet length %d", length)
	}
	if int(length) > len(data) {
		return nil, fmt.Errorf("eap: packet too short, packet says %d but got %d", length, len(data))
	}

	if p.HasType() {
		if length < 5 {
			return nil, errors.New("eap: missing packet type")
		}
		p.Type = PacketType(data[4])
		data = data[5:int(length)]
	} else {
		data = data[4:int(length)]
	}

	p.Data = data

	return p, nil
}
