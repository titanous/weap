package eaptls

import (
	"bytes"
	"crypto/tls"
	"io"
	"sync"
)

type ResponseWriter interface {
	Request(*Packet)
	Success(*Packet, *AuthInfo)
	Failure()
}

type Request struct {
	State string
	*Packet
}

type AuthInfo struct {
	TLSInfo    *tls.ConnectionState
	CommonName string
	SendKey    []byte
	RecvKey    []byte
}

type conn struct {
	mtx       sync.Mutex
	clientBuf *bytes.Buffer
	serverBuf *bytes.Buffer
	clientW   *io.PipeWriter
	keyBuf    *bytes.Buffer
	conn      *tls.Conn
}

type Server struct {
	config *tls.Config
	mtx    sync.Mutex
	conns  map[string]*conn
	config *tls.Config
}

const maxMessageLength = 8000

func (s *Server) ServeEAPTLS(req *Request, w ResponseWriter) {
	if req.State == "" {
		// generate state
		// initialize conn
		// send access-challenge
	}
	if len(req.State) != 32 {
		// TODO: error
	}
	s.mtx.Lock()
	conn := s.conns[req.State]
	s.mtx.Unlock()
	if conn == nil {
		// send error
	}
	conn.mtx.Lock()
	defer conn.mtx.Unlock()

	if req.Flags&FlagLength == 1 {
		if req.Length > maxMessageLength {
			// send error
		}
		conn.clientBuf = &bytes.NewBuffer{}
		conn.clientBuf.Grow(int(req.Length))
	}

	if req.Flags&FlagMore == 1 {
		if conn.clientBuf == nil {
			// unexpected fragment (no length provided) send error
		}
		if len(req.Data)+conn.clientBuf.Len() > conn.clientBuf.Cap() {
			// unexpected data, send error
		}
		conn.clientBuf.Write(req.Data)
		if conn.clientBuf.Len() < conn.clientBuf.Cap() {
			// return continue
		}
	}

	if conn.conn == nil {
		config := s.config.Clone()
		config.KeyLogWriter = conn.keyBuf
	}
	// pump

	conn.clientBuf = nil
}
