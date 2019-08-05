package radius_eaptls

import (
	"github.com/titanous/weap/eap"
	"github.com/titanous/weap/eaptls"
	"github.com/titanous/weap/radius_eaptls/mppe"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
)

func NewHandler(s *eaptls.Server, l eaptls.Logger) radius.Handler {
	return &handler{s: s, log: l}
}

type handler struct {
	s   *eaptls.Server
	log eaptls.Logger
}

func reject(w radius.ResponseWriter, r *radius.Request) error {
	return w.Write(r.Response(radius.CodeAccessReject))
}

func (h *handler) ServeRADIUS(w radius.ResponseWriter, r *radius.Request) {
	if r.Code != radius.CodeAccessRequest {
		h.log.Printf("got unexpected %s from %s, ignoring", r.Code, r.RemoteAddr)
		return
	}

	req := &eaptls.Request{
		ClientUsername: rfc2865.UserName_GetString(r.Packet),
		ClientMAC:      rfc2865.CallingStationID_GetString(r.Packet),
		State:          rfc2865.State_Get(r.Packet),
	}

	eapData, err := rfc2869.EAPMessage_Lookup(r.Packet)
	if err != nil {
		h.log.Printf("error reading EAP data from %s", r.RemoteAddr)
		_ = reject(w, r)
		return
	}

	eapPacket, err := eap.DecodePacket(eapData)
	if err != nil {
		h.log.Printf("error decoding EAP packet from %s: %s", r.RemoteAddr, err)
		_ = reject(w, r)
		return
	}

	rw := &responseWriter{
		r:      r,
		w:      w,
		eapReq: eapPacket,
		tlsReq: req,
	}

	if eapPacket.Code != eap.CodeRequest {
		h.log.Printf("unexpected EAP code %s from %s, expected CodeRequest", eapPacket.Code, r.RemoteAddr)
		rw.Reject()
		return
	}

	switch eapPacket.Type {
	case eap.TypeIdentity:
		h.s.ServeNewChallenge(req, rw)
	case eap.TypeTLS:
		req.Packet, err = eaptls.DecodePacket(eapPacket)
		if err != nil {
			h.log.Printf("error decoding EAP-TLS packet from %s: %s", r.RemoteAddr, err)
			_ = reject(w, r)
			return
		}
		h.s.ServeEAPTLS(req, rw)
	default:
		h.log.Printf("unexepcted EAP packet type %s from %s", eapPacket.Type, r.RemoteAddr)
		rw.Reject()
		return
	}
}

type responseWriter struct {
	r      *radius.Request
	w      radius.ResponseWriter
	eapReq *eap.Packet
	tlsReq *eaptls.Request
	state  []byte
}

func (w *responseWriter) SetState(state []byte) {
	w.state = state
}

func (w *responseWriter) Challenge(pkt *eaptls.Packet) {
	pkt.Outer.Identifier = w.eapReq.Identifier
	pkt.Outer.Code = eap.CodeResponse
	pkt.Outer.Type = eap.TypeTLS
	res := w.r.Response(radius.CodeAccessChallenge)
	if len(w.tlsReq.State) > 0 && len(w.state) == 0 {
		w.state = w.tlsReq.State
	}
	_ = rfc2865.State_Set(res, w.state)
	_ = rfc2869.EAPMessage_Set(res, pkt.Encode(nil))
	_ = w.w.Write(res)
}

func (w *responseWriter) Accept(info *eaptls.AuthInfo) {
	eapRes := w.eapReq.Response(eap.CodeSuccess)
	res := w.r.Response(radius.CodeAccessAccept)
	_ = rfc2869.EAPMessage_Set(res, eapRes.Encode(nil))
	_ = mppe.MSMPPESendKey_Set(res, info.SendKey)
	_ = mppe.MSMPPERecvKey_Set(res, info.RecvKey)
	if info.CommonName != "" {
		_ = rfc2865.UserName_AddString(res, info.CommonName)
	}
	_ = w.w.Write(res)
}

func (w *responseWriter) Reject() {
	eapRes := w.eapReq.Response(eap.CodeFailure)
	res := w.r.Response(radius.CodeAccessReject)
	_ = rfc2869.EAPMessage_Set(res, eapRes.Encode(nil))
	_ = w.w.Write(res)
}
