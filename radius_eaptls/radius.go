package radius_eaptls

import (
	"crypto/hmac"
	"crypto/md5"
	"sync"
	"time"

	"github.com/titanous/weap/eap"
	"github.com/titanous/weap/eaptls"
	"github.com/titanous/weap/radius_eaptls/mppe"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
)

func NewHandler(s *eaptls.Server, l eaptls.Logger) radius.Handler {
	return &handler{
		s:        s,
		log:      l,
		sessions: make(map[string]*session),
	}
}

type handler struct {
	s   *eaptls.Server
	log eaptls.Logger

	mtx      sync.Mutex
	sessions map[string]*session
}

func (h *handler) addResponse(r *radius.Packet) {
	state := rfc2865.State_Get(r)
	if len(state) == 0 {
		return
	}
	h.mtx.Lock()
	sess, ok := h.sessions[string(state)]
	if !ok {
		sess = &session{
			id:        string(state),
			h:         h,
			gcTimer:   time.NewTimer(sessionTimeout),
			responses: make(map[byte]*radius.Packet),
		}
		h.sessions[sess.id] = sess
		go sess.gc()
	}
	h.mtx.Unlock()

	sess.touch()
	sess.mtx.Lock()
	sess.responses[r.Identifier] = r
	sess.mtx.Unlock()
}

type session struct {
	id        string
	h         *handler
	gcTimer   *time.Timer
	mtx       sync.Mutex
	responses map[byte]*radius.Packet
}

const sessionTimeout = 60 * time.Second

func (s *session) gc() {
	<-s.gcTimer.C
	s.h.log.Printf("GCing session state=%x", s.id)
	s.gcTimer.Stop()
	s.h.mtx.Lock()
	delete(s.h.sessions, s.id)
	s.h.mtx.Unlock()
}

func (s *session) touch() {
	s.gcTimer.Reset(sessionTimeout)
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

	h.mtx.Lock()
	sess, ok := h.sessions[string(req.State)]
	h.mtx.Unlock()
	if ok {
		sess.mtx.Lock()
		res, ok := sess.responses[r.Identifier]
		sess.mtx.Unlock()
		if ok {
			w.Write(res)
			h.log.Printf("returning cached response to duplicate request state=%x identifier=%d", r.Identifier, req.State)
			return
		}
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
		h:      h,
		r:      r,
		w:      w,
		eapReq: eapPacket,
		tlsReq: req,
	}

	if eapPacket.Code != eap.CodeResponse {
		h.log.Printf("unexpected EAP code %s from %s, expected Response", eapPacket.Code, r.RemoteAddr)
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
		h.log.Printf("unexpected EAP packet type %s from %s", eapPacket.Type, r.RemoteAddr)
		rw.Reject()
		return
	}
}

func addAuthenticator(p *radius.Packet) {
	_ = rfc2865.FramedMTU_Set(p, 1400)
	_ = rfc2869.MessageAuthenticator_Set(p, make([]byte, 16))
	hash := hmac.New(md5.New, p.Secret)
	b, _ := p.Encode()
	copy(b[4:20], p.Authenticator[:]) // use the request Authenticator
	hash.Write(b)
	_ = rfc2869.MessageAuthenticator_Set(p, hash.Sum(nil))
}

type responseWriter struct {
	h      *handler
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
	pkt.Outer.Identifier = w.eapReq.Identifier + 1
	pkt.Outer.Code = eap.CodeRequest
	pkt.Outer.Type = eap.TypeTLS
	res := w.r.Response(radius.CodeAccessChallenge)
	if len(w.tlsReq.State) > 0 && len(w.state) == 0 {
		w.state = w.tlsReq.State
	}
	_ = rfc2865.State_Set(res, w.state)
	_ = rfc2869.EAPMessage_Set(res, pkt.Encode(nil))
	addAuthenticator(res)
	w.h.addResponse(res)
	_ = w.w.Write(res)
}

func (w *responseWriter) Accept(info *eaptls.AuthInfo) {
	eapRes := w.eapReq.Response(eap.CodeSuccess)
	res := w.r.Response(radius.CodeAccessAccept)
	rfc2869.EAPMessage_Set(res, eapRes.Encode(nil))
	_ = mppe.MSMPPESendKey_Set(res, info.SendKey)
	_ = mppe.MSMPPERecvKey_Set(res, info.RecvKey)
	if info.CommonName != "" {
		_ = rfc2865.UserName_AddString(res, info.CommonName)
	}
	addAuthenticator(res)
	w.h.addResponse(res)
	_ = w.w.Write(res)
}

func (w *responseWriter) Reject() {
	eapRes := w.eapReq.Response(eap.CodeFailure)
	res := w.r.Response(radius.CodeAccessReject)
	_ = rfc2869.EAPMessage_Set(res, eapRes.Encode(nil))
	addAuthenticator(res)
	w.h.addResponse(res)
	_ = w.w.Write(res)
}
