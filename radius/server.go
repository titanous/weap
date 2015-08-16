package radius

import (
	"net"
	"sync"
	"time"
)

func Serve(c net.PacketConn) error {
	server := newServer()
	for {
		// TODO: use sync.Pool
		raw := make([]byte, packetMaxLength)
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
		server.handlePacket(packet, addr)
	}
}

type op int

const (
	opDupe op = iota
	opCancel
)

type requestID struct {
	addr     string
	packetID byte
}

type server struct {
	mtx  sync.RWMutex
	reqs map[requestID]*request
}

type request struct {
	addr    net.Addr
	control chan op
	packet  *Packet
}

func newServer() *server {
	return &server{reqs: make(map[requestID]*request)}
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
		// TODO: return raw to pool
	}
	s.mtx.RUnlock()

	// process a new packet
	s.mtx.Lock()
	defer s.mtx.Unlock()
	req := &request{
		addr:    addr,
		control: make(chan op, 1),
		packet:  packet,
	}
	s.reqs[reqID] = req
	go s.handleRequest(reqID, req)
}

func (s *server) drop(id requestID) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	delete(s.reqs, id)
}

const cleanupDelay = 5 * time.Second

func (s *server) handleRequest(reqID requestID, req *request) {
	var resp *Packet
	var cleanupTimer *time.Timer
	responseCh := make(chan *Packet, 1)

	// TODO: send to handler

	defer func() {
		s.mtx.Lock()
		delete(s.reqs, reqID)
		s.mtx.Unlock()

		if cleanupTimer != nil {
			cleanupTimer.Stop()
		}

		// TODO: return raw buffer to pool
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
				// TODO: resend response
				cleanupTimer.Reset(cleanupDelay)
			case opCancel:
				return
			}
		case resp = <-responseCh:
			// TODO: add authenticator
			// TODO: send

			// wait for a bit to make sure we catch any dupes,
			// they will be treated as resend requests
			cleanupTimer = time.NewTimer(cleanupDelay)
		case <-cleanupTimer.C:
			return
		}
	}
}
