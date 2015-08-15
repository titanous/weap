package radius

import (
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
	Identifier    byte
	Authenticator []byte // 16 bytes
	Attributes    []Attribute
}

type Attribute struct {
	Type AttributeType
	Data []byte
}

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

	length := int(binary.BigEndian.Uint16(data[2:]))
	if length < 20 || length > 4096 {
		return nil, fmt.Errorf("radius: invalid packet length %d", length)
	}
	if length > len(data) {
		return nil, fmt.Errorf("radius: packet too short, packet says %d but got %d", length, len(data))
	}
	data = data[4:length]

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
		if len(data) < attrLen {
			return nil, fmt.Errorf("radius: unexpected packet end reading attribute %d, type %d, attribute says %d got %d", len(p.Attributes), attr.Type, attrLen, len(data))
		}
		if attrLen > 0 {
			attr.Data = data[2:attrLen]
		}
		data = data[attrLen:]
		p.Attributes = append(p.Attributes, attr)
	}

	return &p, nil
}
