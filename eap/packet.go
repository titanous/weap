package eap

import (
	"encoding/binary"
	"errors"
	"fmt"
)

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

type TLSPacketFlag byte

const (
	FlagLength TLSPacketFlag = 1 << 7
	FlagMore   TLSPacketFlag = 1 << 6
	FlagStart  TLSPacketFlag = 1 << 5
)

type Packet struct {
	Code       PacketCode
	Type       PacketType
	Identifier byte

	Flags     TLSPacketFlag
	TLSLength uint32
	Data      []byte
}

func (p *Packet) Encode(buf []byte) []byte {
	length := uint16(4 + len(p.Data))
	if p.Code == CodeRequest || p.Code == CodeResponse {
		length += 1
	}
	if p.Type == TypeTLS {
		length += 1
		if p.Flags&FlagLength != 0 {
			length += 4
		}
	}

	buf = append(buf, byte(p.Code))
	buf = append(buf, p.Identifier)
	buf = append(buf, byte(length>>8), byte(length))
	if p.HasType() {
		buf = append(buf, byte(p.Type))
	}
	if p.Type == TypeTLS {
		buf = append(buf, byte(p.Flags))
		if p.Flags&FlagLength != 0 {
			buf = append(buf,
				byte(p.TLSLength>>24),
				byte(p.TLSLength>>16),
				byte(p.TLSLength>>8),
				byte(p.TLSLength),
			)
		}
	}
	buf = append(buf, p.Data...)

	return buf
}

func (p *Packet) HasType() bool {
	return p.Code == CodeRequest || p.Code == CodeResponse
}

func DecodePacket(data []byte) (*Packet, error) {
	if len(data) < 4 {
		return nil, errors.New("eap: packet is too short")
	}

	var p Packet
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

		if p.Type == TypeTLS {
			if len(data) < 1 {
				return nil, errors.New("eap: missing flags")
			}
			p.Flags = TLSPacketFlag(data[0])
			data = data[1:]
			if p.Flags&FlagLength != 0 {
				if len(data) < 4 {
					return nil, errors.New("eap: missing TLS length")
				}
				p.TLSLength = binary.BigEndian.Uint32(data)
				data = data[4:]
			}
		}
	} else {
		data = data[4:int(length)]
	}

	p.Data = data

	return &p, nil
}
