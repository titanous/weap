package radius_eaptls

import (
	"github.com/titanous/weap/eap"
	"github.com/titanous/weap/eaptls"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
)

func NewHandler(s *eaptls.Server, authKey []byte) radius.Handler {
	return &handler{
		s: s,
		k: authKey,
	}
}

type handler struct {
	s *eaptls.Server
	k []byte
}

func (h *handler) ServeRADIUS(w radius.ResponseWriter, r *radius.Request) {
	// if not access-request, ignore

	req := &eaptls.Request{
		ClientUsername: rfc2865.UserName_GetString(r.Packet),
		ClientMAC:      rfc2865.CallingStationID_GetString(r.Packet),
		State:          rfc2865.State_Get(r.Packet),
	}

	eapData, err := rfc2869.EAPMessage_Lookup(r.Packet)
	if err != nil {
		// log/error
		return
	}

	eapPacket, err := eap.DecodePacket(eapData)
	if err != nil {
		// log/error
		return
	}

	switch eapPacket.Type {
	case eap.TypeIdentity:
		h.s.ServeNewChallenge(req, &responseWriter{rw: w})
	case eap.TypeTLS:
		req.Packet, err = eaptls.DecodePacket(eapPacket)
		if err != nil {
			//log/error
			return
		}
		h.s.ServeEAPTLS(req, &responseWriter{rw: w})
	default:
		// log/error
		return
	}
}

type responseWriter struct {
	state []byte
	rw    radius.ResponseWriter
}

func (w *responseWriter) SetState(state []byte) {
	w.state = state
}

func (w *responseWriter) Challenge(pkt *eaptls.Packet) {

}

func (w *responseWriter) Accept(info *eaptls.AuthInfo) {

}

func (w *responseWriter) Reject() {

}
