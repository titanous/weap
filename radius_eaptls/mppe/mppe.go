package mppe

import (
	"crypto/rand"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

const (
	_Microsoft_VendorID = 311
)

func _Microsoft_AddVendor(p *radius.Packet, typ byte, attr radius.Attribute) (err error) {
	var vsa radius.Attribute
	vendor := make(radius.Attribute, 2+len(attr))
	vendor[0] = typ
	vendor[1] = byte(len(vendor))
	copy(vendor[2:], attr)
	vsa, err = radius.NewVendorSpecific(_Microsoft_VendorID, vendor)
	if err != nil {
		return
	}
	p.Add(rfc2865.VendorSpecific_Type, vsa)
	return
}

func _Microsoft_SetVendor(p *radius.Packet, typ byte, attr radius.Attribute) (err error) {
	for i := 0; i < len(p.Attributes[rfc2865.VendorSpecific_Type]); {
		vendorID, vsa, err := radius.VendorSpecific(p.Attributes[rfc2865.VendorSpecific_Type][i])
		if err != nil || vendorID != _Microsoft_VendorID {
			i++
			continue
		}
		for j := 0; len(vsa[j:]) >= 3; {
			vsaTyp, vsaLen := vsa[0], vsa[1]
			if int(vsaLen) > len(vsa[j:]) || vsaLen < 3 {
				i++
				break
			}
			if vsaTyp == typ {
				vsa = append(vsa[:j], vsa[j+int(vsaLen):]...)
			}
			j += int(vsaLen)
		}
		if len(vsa) > 0 {
			copy(p.Attributes[rfc2865.VendorSpecific_Type][i][4:], vsa)
			i++
		} else {
			p.Attributes[rfc2865.VendorSpecific_Type] = append(p.Attributes[rfc2865.VendorSpecific_Type][:i], p.Attributes[rfc2865.VendorSpecific_Type][i+i:]...)
		}
	}
	return _Microsoft_AddVendor(p, typ, attr)
}

func MSMPPESendKey_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	var salt [2]byte
	_, err = rand.Read(salt[:])
	if err != nil {
		return
	}
	salt[0] |= 0x80
	a, err = radius.NewTunnelPassword(value, salt[:], p.Secret, p.Authenticator[:])
	if err != nil {
		return
	}
	return _Microsoft_SetVendor(p, 16, a)
}
func MSMPPERecvKey_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	var salt [2]byte
	_, err = rand.Read(salt[:])
	if err != nil {
		return
	}
	salt[0] |= 0x80
	a, err = radius.NewTunnelPassword(value, salt[:], p.Secret, p.Authenticator[:])
	if err != nil {
		return
	}
	return _Microsoft_SetVendor(p, 17, a)
}
