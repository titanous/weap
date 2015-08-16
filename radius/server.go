package radius

import (
	"crypto/md5"
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

type ResponseWriter interface {
	// Write encodes and writes the response packet to the client.
	// It must only be called once.
	Write(*Packet) error
}

type Request struct {
	// Addr is the address of the client that sent the request Packet.
	Addr net.Addr

	// Packet is the request packet, it must not be modified and will not be
	// valid after the Handler has been returned from.
	Packet *Packet
}

var bufPool = &sync.Pool{
	New: func() interface{} { return make([]byte, packetMaxLength) },
}

func Serve(c PacketConn, h Handler, secret []byte) error {
	server := newServer(c, h, secret)
	for {
		raw := bufPool.Get().([]byte)
		n, addr, err := c.ReadFrom(raw)
		if err != nil {
			// TODO: check retryable
			return err
		}
		packet, err := DecodePacket(raw[:n])
		if err != nil {
			// TODO: log
			continue
		}
		if packet.Type != TypeAccessRequest {
			// TODO: log
			continue
		}
		server.handlePacket(packet, addr, raw)
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
	}
}

func (s *server) handlePacket(packet *Packet, addr net.Addr, raw []byte) {
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
	go s.handleRequest(reqID, req, raw)
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

func (s *server) handleRequest(reqID requestID, req *request, rawReq []byte) {
	var resp []byte
	var cleanupTimer *time.Timer
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

		bufPool.Put(rawReq)
		if resp != nil {
			bufPool.Put(resp)
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
			resp = bufPool.Get().([]byte)
			resp = resPacket.Encode(resp[:0])
			addResponseAuthenticator(resp, req.packet.Authenticator, s.secret)
			_, err := s.conn.WriteTo(resp, req.addr)
			w.err <- err

			// wait for a bit to make sure we catch any dupes,
			// they will be treated as resend requests
			cleanupTimer = time.NewTimer(cleanupDelay)
			w.ch = nil
		case <-cleanupTimer.C:
			return
		}
	}

}

func responseAuthenticator(response, requestAuthenticator, secret, dest []byte) []byte {
	h := md5.New()
	h.Write(response[:4])
	h.Write(requestAuthenticator)
	if len(response) > 20 {
		h.Write(response[20:])
	}
	h.Write(secret)
	return h.Sum(dest)
}

// addResponseAuthenticator calculates a response authenticator and writes
// it into an encoded packet.
func addResponseAuthenticator(response, requestAuthenticator, secret []byte) {
	responseAuthenticator(response, requestAuthenticator, secret, response[4:4])
}

// CalculateAuthenticator calculates a response authenticator and returns it.
func CalculateAuthenticator(response, requestAuthenticator, secret []byte) []byte {
	return responseAuthenticator(response, requestAuthenticator, secret, nil)
}
