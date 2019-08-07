package eaptls

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

type ResponseWriter interface {
	SetState([]byte)
	Challenge(*Packet)
	Accept(*AuthInfo)
	Reject()
}

type Request struct {
	*Packet
	State          []byte
	ClientUsername string
	ClientMAC      string
}

type AuthInfo struct {
	TLSInfo    *tls.ConnectionState
	CommonName string
	SendKey    []byte
	RecvKey    []byte
}

type conn struct {
	mtx       sync.Mutex
	id        string
	server    *Server
	clientBuf *blockingReaderBuf
	serverBuf *blockingReaderBuf
	conn      *tls.Conn
	done      chan struct{}
	gcTimer   *time.Timer

	handshakeResult chan error

	success *AuthInfo
}

func (c *conn) nextDataPacket(first bool) *Packet {
	size := c.serverBuf.Len()
	if size <= c.server.maxDataLen {
		return &Packet{Data: c.serverBuf.Next(size)}
	}
	p := &Packet{
		Data: c.serverBuf.Next(c.server.maxDataLen),
	}
	p.Flags = FlagMore
	if first {
		p.Length = uint32(size)
		p.Flags |= FlagLength
	}
	return p
}

const connTimeout = 60 * time.Second

func (c *conn) gc() {
	c.gcTimer = time.NewTimer(connTimeout)
	select {
	case <-c.done:
	case <-c.gcTimer.C:
		c.server.log.Printf("conn timed out, GCing state=%x", c.id)
	}
	c.gcTimer.Stop()
	c.server.mtx.Lock()
	delete(c.server.conns, c.id)
	c.server.mtx.Unlock()
}

func (c *conn) touch() {
	c.gcTimer.Reset(connTimeout)
}

func (c *conn) close() {
	if c.clientBuf == nil {
		c.clientBuf.Close()
	}
	if c.serverBuf == nil {
		c.serverBuf.Close()
	}
	close(c.done)
}

type Logger interface {
	Printf(string, ...interface{})
}

type nullLogger struct{}

func (nullLogger) Printf(string, ...interface{}) {}

type ServerConfig struct {
	// MaxDataLen is the maximum length of the data section of an EAP-TLS packet without fragmentation. It defaults to 1000.
	MaxDataLen int

	// TLSConfig is the TLS server configuration, it must not be nil.
	TLSConfig *tls.Config

	// Logger a logger that will be used to log debug output.
	Logger Logger
}

func NewServer(conf *ServerConfig) (*Server, error) {
	if conf.TLSConfig == nil {
		return nil, fmt.Errorf("eaptls: missing TLSConfig")
	}
	s := &Server{
		maxDataLen: conf.MaxDataLen,
		config:     conf.TLSConfig,
		conns:      make(map[string]*conn),
		log:        conf.Logger,
	}
	if s.log == nil {
		s.log = conf.Logger
	}
	if s.maxDataLen == 0 {
		s.maxDataLen = 1000
	}
	return s, nil
}

type Server struct {
	maxDataLen int // default to 1000
	config     *tls.Config
	mtx        sync.Mutex
	conns      map[string]*conn
	log        Logger
}

const maxMessageLength = 65536

func (s *Server) ServeNewChallenge(req *Request, w ResponseWriter) {
	state := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, state); err != nil {
		panic(err)
	}
	w.SetState(state)
	conn := &conn{
		id:     string(state),
		server: s,
		done:   make(chan struct{}),
	}

	s.mtx.Lock()
	s.conns[string(state)] = conn
	s.mtx.Unlock()
	go conn.gc()

	s.log.Printf("initialized handshake username=%s mac=%s state=%x", req.ClientUsername, req.ClientMAC, state)
	p := &Packet{}
	p.Flags = FlagStart
	w.Challenge(p)
}

func (s *Server) ServeEAPTLS(req *Request, w ResponseWriter) {
	log := func(msg string) {
		s.log.Printf(msg+" username=%s mac=%s state=%x", req.ClientMAC, req.ClientUsername, req.State)
	}
	if len(req.State) != 16 {
		log("invalid state value")
		w.Reject()
		return
	}
	s.mtx.Lock()
	conn := s.conns[string(req.State)]
	s.mtx.Unlock()
	if conn == nil {
		log("unknown state")
		w.Reject()
		return
	}
	conn.mtx.Lock()
	defer conn.mtx.Unlock()
	conn.touch()

	if conn.serverBuf != nil && conn.serverBuf.Len() > 0 {
		// we still have a buffer to send in fragments
		if len(req.Data) > 0 {
			// since we haven't finished sending, we shouldn't have any data from the peer
			log("unexpected data received while sending fragmented data, rejecting")
			w.Reject()
			return
		}

		w.Challenge(conn.nextDataPacket(false))
		return
	}

	if conn.success != nil {
		log("handshake success, accepting")
		conn.close()
		w.Accept(conn.success)
		return
	}

	if req.Flags&FlagLength == 1 && req.Length > maxMessageLength {
		log("length exceeds max message, rejecting")
		conn.close()
		w.Reject()
		return
	}

	if conn.clientBuf == nil {
		conn.clientBuf = newBlockingReaderBuf()
	}
	if len(req.Data)+conn.clientBuf.Len() > maxMessageLength {
		log("combined length exceeds max message, rejecting")
		conn.close()
		w.Reject()
		return
	}

	if req.Flags&FlagMore == 1 {
		log("received fragment")
		conn.clientBuf.WriteWithoutUnblock(req.Data)
		w.Challenge(&Packet{})
		return
	} else {
		log("received data")
		conn.clientBuf.Write(req.Data)
	}

	if conn.conn == nil {
		conn.serverBuf = newBlockingReaderBuf()
		conn.conn = tls.Server(&netConnStub{Writer: conn.serverBuf, Reader: conn.clientBuf}, s.config)
	}

	if conn.handshakeResult == nil {
		conn.handshakeResult = make(chan error, 1)
		go func() {
			conn.handshakeResult <- conn.conn.Handshake()
		}()
	}

	if conn.clientBuf.Blocked() {
		panic("TLS handshake state is blocked on client read unexpectedly, rejecting")
		conn.close()
		w.Reject()
		return
	}

	select {
	case err := <-conn.handshakeResult:
		if err != nil {
			log(fmt.Sprintf("TLS handshake error err=%s", err))
			conn.close()
			w.Reject()
			break
		}
		state := conn.conn.ConnectionState()
		// TODO: check certificate revocation
		var key []byte
		if state.Version > tls.VersionTLS12 { // TLS 1.3
			key, err = state.ExportKeyingMaterial("EXPORTER_EAP_TLS_Key_Material", []byte{0x0d}, 128)
		} else {
			key, err = state.ExportKeyingMaterial("client EAP encryption", nil, 128)
		}
		if err != nil {
			log(fmt.Sprintf("EKM error, rejecting err=%s", err))
			conn.close()
			w.Reject()
			return
		}
		conn.success = &AuthInfo{
			TLSInfo: &state,
			RecvKey: key[:32],
			SendKey: key[32:64],
		}
		if len(state.VerifiedChains) > 0 {
			conn.success.CommonName = state.VerifiedChains[0][0].Subject.CommonName
		}
		log(fmt.Sprintf("TLS handshake success cn=%s tls=%x cipher=%x", conn.success.CommonName, state.Version, state.CipherSuite))
		if state.Version > tls.VersionTLS12 {
			// send application data frame to indicate completion (for TLS 1.3)
			conn.conn.Write([]byte{0})
		}
		// the select we're in can result in sending the finished message before we get here
		if conn.serverBuf.Len() == 0 {
			log("handshake complete, accepting")
			conn.close()
			w.Accept(conn.success)
			return
		}
	case <-conn.serverBuf.Available():
		log("sending handshake data")
	}

	w.Challenge(conn.nextDataPacket(true))
}

func newBlockingReaderBuf() *blockingReaderBuf {
	return &blockingReaderBuf{
		cond:      sync.Cond{L: &sync.Mutex{}},
		available: make(chan struct{}, 1),
		unblocked: make(chan struct{}),
	}
}

type blockingReaderBuf struct {
	buf       bytes.Buffer
	cond      sync.Cond
	closed    bool
	blocked   bool
	available chan struct{}
	unblocked chan struct{}
}

func (b *blockingReaderBuf) Read(p []byte) (int, error) {
	b.cond.L.Lock()
	defer b.cond.L.Unlock()

	if b.closed && b.buf.Len() == 0 {
		return 0, io.EOF
	}

	if b.buf.Len() == 0 {
		b.blocked = true
		b.cond.Wait()
		b.blocked = false
		defer func() { b.unblocked <- struct{}{} }()
	}

	if b.closed && b.buf.Len() == 0 {
		return 0, io.EOF
	}

	return b.buf.Read(p)
}

func (b *blockingReaderBuf) Write(p []byte) (int, error) {
	b.write(p, true)
	return len(p), nil
}

func (b *blockingReaderBuf) WriteWithoutUnblock(p []byte) {
	b.write(p, false)
}

func (b *blockingReaderBuf) write(p []byte, unblock bool) {
	b.cond.L.Lock()
	b.buf.Write(p)
	var blocked bool
	if unblock {
		select {
		case b.available <- struct{}{}:
		default:
		}
		blocked = b.blocked
		b.cond.Broadcast()
	}
	b.cond.L.Unlock()
	if blocked {
		<-b.unblocked
	}
}

func (b *blockingReaderBuf) Close() {
	b.cond.L.Lock()
	defer b.cond.L.Lock()
	b.closed = true
	b.cond.Broadcast()
}

func (b *blockingReaderBuf) Len() int {
	b.cond.L.Lock()
	defer b.cond.L.Unlock()
	return b.buf.Len()
}

func (b *blockingReaderBuf) Next(n int) []byte {
	b.cond.L.Lock()
	defer b.cond.L.Unlock()
	return b.buf.Next(n)
}

func (b *blockingReaderBuf) Blocked() bool {
	b.cond.L.Lock()
	defer b.cond.L.Unlock()
	return b.blocked
}

func (b *blockingReaderBuf) Available() <-chan struct{} {
	return b.available
}

type netConnStub struct {
	io.Reader
	io.Writer
}

func (c *netConnStub) LocalAddr() net.Addr {
	return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func (c *netConnStub) RemoteAddr() net.Addr {
	return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func (c *netConnStub) Close() error { return nil }

func (c *netConnStub) SetDeadline(t time.Time) error { return nil }

func (c *netConnStub) SetReadDeadline(t time.Time) error { return nil }

func (c *netConnStub) SetWriteDeadline(t time.Time) error { return nil }
