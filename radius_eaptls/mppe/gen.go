// Code generated by radius-dict-gen. DO NOT EDIT.

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

func _Microsoft_GetsVendor(p *radius.Packet, typ byte) (values []radius.Attribute) {
	for _, attr := range p.Attributes[rfc2865.VendorSpecific_Type] {
		vendorID, vsa, err := radius.VendorSpecific(attr)
		if err != nil || vendorID != _Microsoft_VendorID {
			continue
		}
		for len(vsa) >= 3 {
			vsaTyp, vsaLen := vsa[0], vsa[1]
			if int(vsaLen) > len(vsa) || vsaLen < 3 {
				break
			}
			if vsaTyp == typ {
				values = append(values, vsa[2:int(vsaLen)])
			}
			vsa = vsa[int(vsaLen):]
		}
	}
	return
}

func _Microsoft_LookupVendor(p *radius.Packet, typ byte) (attr radius.Attribute, ok bool) {
	for _, a := range p.Attributes[rfc2865.VendorSpecific_Type] {
		vendorID, vsa, err := radius.VendorSpecific(a)
		if err != nil || vendorID != _Microsoft_VendorID {
			continue
		}
		for len(vsa) >= 3 {
			vsaTyp, vsaLen := vsa[0], vsa[1]
			if int(vsaLen) > len(vsa) || vsaLen < 3 {
				break
			}
			if vsaTyp == typ {
				return vsa[2:int(vsaLen)], true
			}
			vsa = vsa[int(vsaLen):]
		}
	}
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

func _Microsoft_DelVendor(p *radius.Packet, typ byte) {
vsaLoop:
	for i := 0; i < len(p.Attributes[rfc2865.VendorSpecific_Type]); {
		attr := p.Attributes[rfc2865.VendorSpecific_Type][i]
		vendorID, vsa, err := radius.VendorSpecific(attr)
		if err != nil || vendorID != _Microsoft_VendorID {
			continue
		}
		offset := 0
		for len(vsa[offset:]) >= 3 {
			vsaTyp, vsaLen := vsa[offset], vsa[offset+1]
			if int(vsaLen) > len(vsa) || vsaLen < 3 {
				continue vsaLoop
			}
			if vsaTyp == typ {
				copy(vsa[offset:], vsa[offset+int(vsaLen):])
				vsa = vsa[:len(vsa)-int(vsaLen)]
			} else {
				offset += int(vsaLen)
			}
		}
		if offset == 0 {
			p.Attributes[rfc2865.VendorSpecific_Type] = append(p.Attributes[rfc2865.VendorSpecific_Type][:i], p.Attributes[rfc2865.VendorSpecific_Type][i+1:]...)
		} else {
			i++
		}
	}
	return
}

func MSMPPESendKey_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	var salt [2]byte
	_, err = rand.Read(salt[:])
	if err != nil {
		return
	}
	a, err = radius.NewTunnelPassword(value, salt[:], p.Secret, p.Authenticator[:])
	if err != nil {
		return
	}
	return _Microsoft_AddVendor(p, 16, a)
}

func MSMPPESendKey_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	var salt [2]byte
	_, err = rand.Read(salt[:])
	if err != nil {
		return
	}
	a, err = radius.NewTunnelPassword([]byte(value), salt[:], p.Secret, p.Authenticator[:])
	if err != nil {
		return
	}
	return _Microsoft_AddVendor(p, 16, a)
}

func MSMPPESendKey_Get(p *radius.Packet) (value []byte) {
	value, _ = MSMPPESendKey_Lookup(p)
	return
}

func MSMPPESendKey_GetString(p *radius.Packet) (value string) {
	value, _ = MSMPPESendKey_LookupString(p)
	return
}

func MSMPPESendKey_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range _Microsoft_GetsVendor(p, 16) {
		i, _, err = radius.TunnelPassword(attr, p.Secret, p.Authenticator[:])
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func MSMPPESendKey_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range _Microsoft_GetsVendor(p, 16) {
		var up []byte
		up, _, err = radius.TunnelPassword(attr, p.Secret, p.Authenticator[:])
		if err == nil {
			i = string(up)
		}
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func MSMPPESendKey_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := _Microsoft_LookupVendor(p, 16)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value, _, err = radius.TunnelPassword(a, p.Secret, p.Authenticator[:])
	return
}

func MSMPPESendKey_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := _Microsoft_LookupVendor(p, 16)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var b []byte
	b, _, err = radius.TunnelPassword(a, p.Secret, p.Authenticator[:])
	if err == nil {
		value = string(b)
	}
	return
}

func MSMPPESendKey_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	var salt [2]byte
	_, err = rand.Read(salt[:])
	if err != nil {
		return
	}
	a, err = radius.NewTunnelPassword(value, salt[:], p.Secret, p.Authenticator[:])
	if err != nil {
		return
	}
	return _Microsoft_SetVendor(p, 16, a)
}

func MSMPPESendKey_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	var salt [2]byte
	_, err = rand.Read(salt[:])
	if err != nil {
		return
	}
	a, err = radius.NewTunnelPassword([]byte(value), salt[:], p.Secret, p.Authenticator[:])
	if err != nil {
		return
	}
	return _Microsoft_SetVendor(p, 16, a)
}

func MSMPPESendKey_Del(p *radius.Packet) {
	_Microsoft_DelVendor(p, 16)
}

func MSMPPERecvKey_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	var salt [2]byte
	_, err = rand.Read(salt[:])
	if err != nil {
		return
	}
	a, err = radius.NewTunnelPassword(value, salt[:], p.Secret, p.Authenticator[:])
	if err != nil {
		return
	}
	return _Microsoft_AddVendor(p, 17, a)
}

func MSMPPERecvKey_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	var salt [2]byte
	_, err = rand.Read(salt[:])
	if err != nil {
		return
	}
	a, err = radius.NewTunnelPassword([]byte(value), salt[:], p.Secret, p.Authenticator[:])
	if err != nil {
		return
	}
	return _Microsoft_AddVendor(p, 17, a)
}

func MSMPPERecvKey_Get(p *radius.Packet) (value []byte) {
	value, _ = MSMPPERecvKey_Lookup(p)
	return
}

func MSMPPERecvKey_GetString(p *radius.Packet) (value string) {
	value, _ = MSMPPERecvKey_LookupString(p)
	return
}

func MSMPPERecvKey_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range _Microsoft_GetsVendor(p, 17) {
		i, _, err = radius.TunnelPassword(attr, p.Secret, p.Authenticator[:])
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func MSMPPERecvKey_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range _Microsoft_GetsVendor(p, 17) {
		var up []byte
		up, _, err = radius.TunnelPassword(attr, p.Secret, p.Authenticator[:])
		if err == nil {
			i = string(up)
		}
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func MSMPPERecvKey_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := _Microsoft_LookupVendor(p, 17)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value, _, err = radius.TunnelPassword(a, p.Secret, p.Authenticator[:])
	return
}

func MSMPPERecvKey_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := _Microsoft_LookupVendor(p, 17)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var b []byte
	b, _, err = radius.TunnelPassword(a, p.Secret, p.Authenticator[:])
	if err == nil {
		value = string(b)
	}
	return
}

func MSMPPERecvKey_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	var salt [2]byte
	_, err = rand.Read(salt[:])
	if err != nil {
		return
	}
	a, err = radius.NewTunnelPassword(value, salt[:], p.Secret, p.Authenticator[:])
	if err != nil {
		return
	}
	return _Microsoft_SetVendor(p, 17, a)
}

func MSMPPERecvKey_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	var salt [2]byte
	_, err = rand.Read(salt[:])
	if err != nil {
		return
	}
	a, err = radius.NewTunnelPassword([]byte(value), salt[:], p.Secret, p.Authenticator[:])
	if err != nil {
		return
	}
	return _Microsoft_SetVendor(p, 17, a)
}

func MSMPPERecvKey_Del(p *radius.Packet) {
	_Microsoft_DelVendor(p, 17)
}
