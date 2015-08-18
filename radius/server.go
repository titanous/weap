// Package radius implements RADIUS (RFC 2865) packet encoding/decoding as well
// as a server framework.
package radius

import (
	"crypto/hmac"
	"crypto/md5"
	"log"
	"net"
	"sync"
	"time"
)

type PacketConn interface {
	// ReadFrom reads a packet from the connection,
	// copying the payload into b. It returns the number of
	// bytes copied into b and the return address that
	// was on the packet.
	ReadFrom(b []byte) (n int, addr net.Addr, err error)

	// WriteTo writes a packet with payload b to addr.
	WriteTo(b []byte, addr net.Addr) (n int, err error)
}

type Handler interface {
	ServeRADIUS(ResponseWriter, *Request)
}

type HandlerFunc func(ResponseWriter, *Request)

func (f HandlerFunc) ServeRADIUS(w ResponseWriter, r *Request) {
	f(w, r)
}

type ResponseWriter interface {
	// Write encodes and writes the response packet to the client.
	// It must only be called once.
	Write(*Packet) error
}

type Request struct {
	// Addr is the address of the client that sent the request Packet.
	Addr net.Addr

	// Packet is the request packet.
	Packet *Packet
}

var resBufPool = &sync.Pool{
	New: func() interface{} { return make([]byte, packetMaxLength) },
}

func Serve(c PacketConn, secret []byte, h Handler) error {
	server := newServer(c, h, secret)
	for {
		raw := make([]byte, packetMaxLength)
		n, addr, err := c.ReadFrom(raw)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				log.Printf("radius: got packet read error, retrying in 1s: %s", err)
				time.Sleep(time.Second)
				continue
			}
			return err
		}

		// verify the Message-Authenticator before parsing the packet
		// 38 is the minimum length of a valid packet with a message authenticator
		if n < 38 || !validMessageAuthenticator(raw[:n], secret) {
			log.Printf("radius: error decoding packet from %s: missing or invalid Message-Authenticator", addr)
			continue
		}

		packet, err := DecodePacket(raw[:n])
		if err != nil {
			log.Printf("radius: error decoding packet from %s: %s", addr, err)
			continue
		}
		if packet.Type != TypeAccessRequest {
			log.Printf("radius: got invalid packet type from %s: %s", addr, packet.Type)
			continue
		}
		if len(packet.Attributes) == 0 || packet.Attributes[len(packet.Attributes)-1].Type != AttributeTypeMessageAuthenticator {
			log.Printf("radius: error processing packet from %s: apparently valid Message-Authenticator, but attributes are weird")
			continue
		}

		server.handlePacket(packet, addr)
	}
}

type requestID struct {
	addr     string
	packetID byte
}

type server struct {
	mtx     sync.RWMutex
	reqs    map[requestID]*request
	conn    PacketConn
	handler Handler
	secret  []byte
}

type op byte

const (
	opDupe op = iota
	opCancel
)

type request struct {
	addr    net.Addr
	control chan op
	packet  *Packet
}

func newServer(c PacketConn, h Handler, secret []byte) *server {
	return &server{
		reqs:    make(map[requestID]*request),
		conn:    c,
		handler: h,
		secret:  secret,
	}
}

func (s *server) handlePacket(packet *Packet, addr net.Addr) {
	reqID := requestID{addr.String(), packet.Identifier}

	s.mtx.RLock()
	if existing, ok := s.reqs[reqID]; ok {
		if packet.Equal(existing.packet) {
			// if it's the same packet we already have,
			// notify the request handler
			existing.control <- opDupe
			s.mtx.RUnlock()
			return
		} else {
			// if it's a new packet with the same ID,
			// cancel the existing request, process the new one
			existing.control <- opCancel
		}
	}
	s.mtx.RUnlock()

	// process a new packet
	req := &request{
		addr:    addr,
		control: make(chan op, 1),
		packet:  packet,
	}
	s.mtx.Lock()
	s.reqs[reqID] = req
	s.mtx.Unlock()
	go s.handleRequest(reqID, req)
}

func newResponseWriter() *responseWriter {
	return &responseWriter{
		ch:  make(chan *Packet, 1),
		err: make(chan error, 1),
	}
}

type responseWriter struct {
	ch  chan *Packet
	err chan error
}

func (w *responseWriter) Write(p *Packet) error {
	w.ch <- p
	return <-w.err
}

const cleanupDelay = 5 * time.Second

func (s *server) handleRequest(reqID requestID, req *request) {
	var resp []byte
	var cleanupTimer *time.Timer
	var timerCh <-chan time.Time
	w := newResponseWriter()
	handlerDone := make(chan struct{})

	go func() {
		s.handler.ServeRADIUS(w, &Request{Addr: req.addr, Packet: req.packet})
		close(handlerDone)
	}()

	defer func() {
		s.mtx.Lock()
		delete(s.reqs, reqID)
		s.mtx.Unlock()

		if cleanupTimer != nil {
			cleanupTimer.Stop()
		}

		// wait until the handler is done so that we can return the packet
		// buffer to the pool.
		<-handlerDone

		if resp != nil {
			resBufPool.Put(resp)
		}
	}()

	for {
		select {
		case op := <-req.control:
			switch op {
			case opDupe:
				if resp == nil {
					// still processing, ignore dupe
					continue
				}
				s.conn.WriteTo(resp, req.addr)
				cleanupTimer.Reset(cleanupDelay)
			case opCancel:
				return
			}
		case resPacket := <-w.ch:
			resPacket.Identifier = req.packet.Identifier
			resPacket.Attributes = append(resPacket.Attributes, Attribute{
				Type: AttributeTypeMessageAuthenticator,
				Data: emptyAuthenticator,
			})
			resp = resBufPool.Get().([]byte)
			resp = resPacket.Encode(resp[:0])
			addMessageAuthenticator(resp, req.packet.Authenticator, s.secret)
			addResponseAuthenticator(resp, req.packet.Authenticator, s.secret)
			_, err := s.conn.WriteTo(resp, req.addr)
			w.err <- err

			// wait for a bit to make sure we catch any dupes,
			// they will be treated as resend requests
			cleanupTimer = time.NewTimer(cleanupDelay)
			timerCh = cleanupTimer.C
			w.ch = nil
		case <-timerCh:
			return
		}
	}
}

// addResponseAuthenticator calculates a response authenticator and writes
// it into an encoded packet.
func addResponseAuthenticator(response, requestAuthenticator, secret []byte) {
	h := md5.New()
	h.Write(response[:4])
	h.Write(requestAuthenticator)
	h.Write(response[20:])
	h.Write(secret)
	h.Sum(response[4:4])
}

// addMessageAuthenticator calculates a response message authenticator and
// writes it into an encoded packet. It assumes that the last attribute in the
// packet is an all-zero Message-Authenticator.
func addMessageAuthenticator(response, requestAuthenticator, secret []byte) {
	h := hmac.New(md5.New, secret)
	h.Write(response[:4])
	h.Write(requestAuthenticator)
	h.Write(response[20:])
	startIdx := len(response) - 16
	h.Sum(response[startIdx:startIdx])
}

func validMessageAuthenticator(request, secret []byte) bool {
	h := hmac.New(md5.New, secret)
	startIdx := len(request) - 16
	h.Write(request[:startIdx])
	h.Write(emptyAuthenticator)
	return hmac.Equal(h.Sum(nil), request[startIdx:])
}
