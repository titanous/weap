package radius

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

type PacketType byte

const (
	TypeAccessRequest   PacketType = 1
	TypeAccessAccept    PacketType = 2
	TypeAccessReject    PacketType = 3
	TypeAccessChallenge PacketType = 11
)

type AttributeType byte

type Packet struct {
	Type          PacketType
	Length        uint16
	Identifier    byte
	Authenticator []byte // 16 bytes
	Attributes    []Attribute
}

type Attribute struct {
	Type AttributeType
	Data []byte
}

func (p *Packet) Encode(buf []byte) []byte {
	length := uint16(20)
	for _, attr := range p.Attributes {
		length += 2 + uint16(len(attr.Data))
	}

	buf = append(buf, byte(p.Type))
	buf = append(buf, p.Identifier)
	buf = append(buf, byte(length>>8), byte(length))
	if len(p.Authenticator) != 16 {
		panic(fmt.Errorf("radius: expected authenticator to be 16 bytes, got %d", len(p.Authenticator)))
	}
	buf = append(buf, p.Authenticator...)

	for _, attr := range p.Attributes {
		buf = append(buf, byte(attr.Type))
		buf = append(buf, byte(2+len(attr.Data)))
		buf = append(buf, attr.Data...)
	}

	return buf
}

func (p *Packet) Equal(other *Packet) bool {
	return p.Identifier == other.Identifier && p.Length == other.Length && bytes.Equal(p.Authenticator, other.Authenticator)
}

const packetMaxLength = 4096

func DecodePacket(data []byte) (*Packet, error) {
	if len(data) < 20 {
		return nil, errors.New("radius: packet is too short")
	}

	var p Packet
	p.Type = PacketType(data[0])

	if p.Type != TypeAccessRequest && p.Type != TypeAccessAccept && p.Type != TypeAccessReject && p.Type != TypeAccessChallenge {
		return nil, fmt.Errorf("radius: unknown packet type %d", p.Type)
	}

	p.Identifier = data[1]

	p.Length = binary.BigEndian.Uint16(data[2:])
	if p.Length < 20 || p.Length > packetMaxLength {
		return nil, fmt.Errorf("radius: invalid packet length %d", p.Length)
	}
	if int(p.Length) > len(data) {
		return nil, fmt.Errorf("radius: packet too short, packet says %d but got %d", p.Length, len(data))
	}
	data = data[4:int(p.Length)]

	p.Authenticator = data[:16]
	data = data[16:]

	// read attributes
	for len(data) > 0 {
		if len(data) < 2 {
			return nil, fmt.Errorf("radius: unexpected packet end reading attribute %d", len(p.Attributes))
		}
		var attr Attribute
		attr.Type = AttributeType(data[0])
		attrLen := int(data[1])
		if attrLen < 2 {
			return nil, fmt.Errorf("radius: error reading attribute %d, length is too low: %d", len(p.Attributes), attrLen)
		}
		if len(data) < attrLen {
			return nil, fmt.Errorf("radius: unexpected packet end reading attribute %d, type %d, attribute says %d got %d", len(p.Attributes), attr.Type, attrLen, len(data))
		}
		if attrLen > 2 {
			attr.Data = data[2:attrLen]
		}
		data = data[attrLen:]
		p.Attributes = append(p.Attributes, attr)
	}

	return &p, nil
}
