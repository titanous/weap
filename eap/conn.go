package eap

import (
	"errors"
)

type Conn interface {
	Read() (*Packet, error)
	Write(p *Packet) error
	Close() error
}

// serverConn implements a connection from a client on the server side.
type serverConn struct {
	lastRequest  *Packet
	lastResponse *Packet

	// channels sent to by run()
	reqCh    chan *Packet
	resCh    chan *Packet
	writeErr chan error
	readErr  chan error
}

func (c *serverConn) Read() (*Packet, error) {
	select {
	case p := <-c.reqCh:
		return p, nil
	case err := <-c.readErr:
		return nil, err
	}
}

func (c *serverConn) Write(p *Packet) error {
	c.resCh <- p
	return <-c.writeErr
}

func (c *serverConn) Close() error {
	return nil
}

func (c *serverConn) run(in <-chan *Packet, write func(*Packet) error) {
	for {
		select {
		case packet := <-in:
			if c.lastRequest != nil {
				// if replied, send same response
				if c.lastRequest.Identifier == packet.Identifier && c.lastResponse != nil {
					write(c.lastResponse)
				}
				// if pending or different id, drop
				continue
			}

			// process new request
			c.lastRequest = packet
			c.lastResponse = nil
			c.reqCh <- packet
		case packet := <-c.resCh:
			if c.lastResponse == nil {
				c.writeErr <- errors.New("eap: no pending request")
			}
			c.lastResponse = packet
			c.writeErr <- write(packet)
		}
	}
}
