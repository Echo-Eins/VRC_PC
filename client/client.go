package client

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"vpn-relay/protocol"

	"github.com/pion/dtls/v2"
)

// Handshake contains metadata returned by the discovery exchange with the
// relay server.
type Handshake struct {
	ClientID        [16]byte
	SessionID       [16]byte
	SharedKey       []byte
	ServerPublicKey []byte
	RemoteAddr      *net.UDPAddr
}

type pendingRequest struct {
	ch chan incomingMessage
}

type incomingMessage struct {
	packetType uint32
	payload    []byte
	err        error
}

// Client implements a production-grade client for the VPN relay server.
type Client struct {
	cfg    Config
	logger *logWrapper

	mu          sync.RWMutex
	privateKey  *ecdh.PrivateKey
	clientID    [16]byte
	sessionID   [16]byte
	sharedKey   []byte
	serverAddr  *net.UDPAddr
	dtlsConn    *dtls.Conn
	readCancel  context.CancelFunc
	readDone    chan struct{}
	closed      bool
	nextRequest uint32
	nextConnID  uint32

	pendingMu sync.Mutex
	pending   map[uint32]*pendingRequest

	tcpMu      sync.RWMutex
	tcpStreams map[uint32]*TCPStream

	udpMu       sync.RWMutex
	udpSessions map[uint32]*UDPSession
}

// New creates a new client using the provided configuration.
func New(cfg Config) (*Client, error) {
	cfg.setDefaults()

	c := &Client{
		cfg:         cfg,
		logger:      newLogWrapper(cfg.Logger),
		pending:     make(map[uint32]*pendingRequest),
		tcpStreams:  make(map[uint32]*TCPStream),
		udpSessions: make(map[uint32]*UDPSession),
	}

	c.logger.setDebug(cfg.EnableDebug)

	return c, nil
}

// Discover performs the multicast discovery handshake with the server and
// prepares the client for subsequent DTLS connection establishment.
func (c *Client) Discover(ctx context.Context) (*Handshake, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	curve := ecdh.P256()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ECDH key: %w", err)
	}

	var clientID [16]byte
	if _, err := rand.Read(clientID[:]); err != nil {
		return nil, fmt.Errorf("generate client id: %w", err)
	}

	multicastAddr, err := net.ResolveUDPAddr("udp", c.cfg.MulticastAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve multicast addr: %w", err)
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("listen udp: %w", err)
	}
	defer conn.Close()

	pubBytes := privateKey.PublicKey().Bytes()
	if len(pubBytes) != 65 || pubBytes[0] != 0x04 {
		return nil, fmt.Errorf("unexpected public key format: %d bytes", len(pubBytes))
	}

	packet := make([]byte, 93)
	copy(packet[0:4], []byte(protocol.MagicBytes))
	copy(packet[4:20], clientID[:])
	copy(packet[20:85], pubBytes)
	binary.LittleEndian.PutUint64(packet[85:93], uint64(time.Now().Unix()))

	if deadline, ok := ctx.Deadline(); ok {
		conn.SetWriteDeadline(deadline)
		conn.SetReadDeadline(deadline)
	} else {
		conn.SetWriteDeadline(time.Now().Add(c.cfg.DiscoveryTimeout))
		conn.SetReadDeadline(time.Now().Add(c.cfg.DiscoveryTimeout))
	}

	if _, err := conn.WriteToUDP(packet, multicastAddr); err != nil {
		return nil, fmt.Errorf("send discovery: %w", err)
	}

	buffer := make([]byte, 512)
	n, addr, err := conn.ReadFromUDP(buffer)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("read handshake: %w", err)
	}
	if n < 83 {
		return nil, fmt.Errorf("handshake response too short: %d bytes", n)
	}

	var response protocol.HandshakeResponse
	copy(response.SessionID[:], buffer[0:16])
	copy(response.PublicKey[:], buffer[16:81])
	response.DTLSPort = binary.LittleEndian.Uint16(buffer[81:83])

	serverPub, err := curve.NewPublicKey(response.PublicKey[:])
	if err != nil {
		return nil, fmt.Errorf("parse server public key: %w", err)
	}

	sharedSecret, err := privateKey.ECDH(serverPub)
	if err != nil {
		return nil, fmt.Errorf("ecdh compute: %w", err)
	}

	hasher := sha256.New()
	hasher.Write(sharedSecret)
	hasher.Write([]byte(c.cfg.SharedSecret))
	combined := hasher.Sum(nil)

	remoteAddr := &net.UDPAddr{IP: addr.IP, Port: int(response.DTLSPort)}

	c.mu.Lock()
	c.privateKey = privateKey
	c.clientID = clientID
	c.sessionID = response.SessionID
	c.sharedKey = append([]byte(nil), combined...)
	c.serverAddr = remoteAddr
	c.closed = false
	c.mu.Unlock()

	c.logger.Infof("discovery complete: session=%x remote=%s", response.SessionID[:4], remoteAddr)

	return &Handshake{
		ClientID:        clientID,
		SessionID:       response.SessionID,
		SharedKey:       append([]byte(nil), combined...),
		ServerPublicKey: append([]byte(nil), response.PublicKey[:]...),
		RemoteAddr:      remoteAddr,
	}, nil
}

// Connect establishes the DTLS tunnel using parameters obtained from Discover.
func (c *Client) Connect(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return errors.New("client is closed")
	}
	if c.dtlsConn != nil {
		c.mu.RUnlock()
		return errors.New("DTLS connection already established")
	}
	remoteAddr := c.serverAddr
	c.mu.RUnlock()

	if remoteAddr == nil {
		return errors.New("discovery has not been performed")
	}

	dialCtx, cancel := context.WithTimeout(ctx, c.cfg.DTLSConnectTimeout)
	defer cancel()

	cfg := &dtls.Config{
		PSK: func(hint []byte) ([]byte, error) {
			return []byte(c.cfg.SharedSecret), nil
		},
		PSKIdentityHint: []byte("vpn-relay"),
		CipherSuites:    []dtls.CipherSuiteID{dtls.TLS_PSK_WITH_AES_128_GCM_SHA256},
	}

	conn, err := dtls.DialWithContext(dialCtx, "udp", remoteAddr, cfg)
	if err != nil {
		return fmt.Errorf("dtls dial: %w", err)
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		conn.Close()
		return errors.New("client is closed")
	}
	c.dtlsConn = conn
	readCtx, cancelRead := context.WithCancel(context.Background())
	c.readCancel = cancelRead
	c.readDone = make(chan struct{})
	c.mu.Unlock()

	go c.readLoop(readCtx, conn)

	c.logger.Infof("dtls connected to %s", remoteAddr)
	return nil
}

// Close tears down the client and releases all associated resources.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	cancel := c.readCancel
	conn := c.dtlsConn
	c.dtlsConn = nil
	c.readCancel = nil
	done := c.readDone
	c.readDone = nil
	c.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if conn != nil {
		conn.Close()
	}
	if done != nil {
		<-done
	}

	c.failAllPending(errors.New("client closed"))
	c.closeAllTCPStreams(io.EOF)
	c.closeAllUDPSessions(io.EOF)

	return nil
}

func (c *Client) ensureConnected() (*dtls.Conn, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New("client is closed")
	}
	if c.dtlsConn == nil {
		return nil, errors.New("dtls connection is not established")
	}
	return c.dtlsConn, nil
}

func (c *Client) nextRequestID() uint32 {
	id := atomic.AddUint32(&c.nextRequest, 1)
	if id == 0 {
		id = atomic.AddUint32(&c.nextRequest, 1)
	}
	return id
}

func (c *Client) nextConnectionID() uint32 {
	id := atomic.AddUint32(&c.nextConnID, 1)
	if id == 0 {
		id = atomic.AddUint32(&c.nextConnID, 1)
	}
	return id
}

func (c *Client) sendRequest(ctx context.Context, packetType uint32, payload []byte, expected []uint32) ([]byte, uint32, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	conn, err := c.ensureConnected()
	if err != nil {
		return nil, 0, err
	}

	requestID := c.nextRequestID()
	respCh := make(chan incomingMessage, 1)
	c.pendingMu.Lock()
	c.pending[requestID] = &pendingRequest{ch: respCh}
	c.pendingMu.Unlock()

	if err := c.writePacket(conn, packetType, requestID, payload); err != nil {
		c.pendingMu.Lock()
		delete(c.pending, requestID)
		c.pendingMu.Unlock()
		return nil, 0, err
	}

	var timeout <-chan time.Time
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.After(time.Until(deadline))
	} else if c.cfg.ResponseTimeout > 0 {
		timeout = time.After(c.cfg.ResponseTimeout)
	}

	select {
	case msg := <-respCh:
		if msg.err != nil {
			return nil, 0, msg.err
		}
		if msg.packetType == protocol.PacketError {
			return nil, 0, fmt.Errorf("server error: %s", string(msg.payload))
		}
		if len(expected) > 0 && !containsUint32(expected, msg.packetType) {
			return nil, 0, fmt.Errorf("unexpected response type %d", msg.packetType)
		}
		return msg.payload, msg.packetType, nil
	case <-timeout:
		c.pendingMu.Lock()
		delete(c.pending, requestID)
		c.pendingMu.Unlock()
		return nil, 0, fmt.Errorf("request %d timed out", requestID)
	case <-ctx.Done():
		c.pendingMu.Lock()
		delete(c.pending, requestID)
		c.pendingMu.Unlock()
		return nil, 0, ctx.Err()
	}
}

func (c *Client) writePacket(conn *dtls.Conn, packetType, requestID uint32, payload []byte) error {
	header := protocol.PacketHeader{
		Type:      packetType,
		ID:        requestID,
		Length:    uint32(len(payload)),
		Timestamp: time.Now().Unix(),
	}

	packet := make([]byte, 20+len(payload))
	binary.LittleEndian.PutUint32(packet[0:4], header.Type)
	binary.LittleEndian.PutUint32(packet[4:8], header.ID)
	binary.LittleEndian.PutUint32(packet[8:12], header.Length)
	binary.LittleEndian.PutUint64(packet[12:20], uint64(header.Timestamp))
	copy(packet[20:], payload)

	if err := conn.SetWriteDeadline(time.Now().Add(c.cfg.ResponseTimeout)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	if _, err := conn.Write(packet); err != nil {
		return fmt.Errorf("dtls write: %w", err)
	}
	return nil
}

func (c *Client) readLoop(ctx context.Context, conn *dtls.Conn) {
	defer close(c.readDone)

	buffer := make([]byte, c.cfg.MaxPacketSize)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			c.logger.Errorf("set read deadline: %v", err)
			c.failAllPending(err)
			return
		}

		n, err := conn.Read(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			if errors.Is(err, io.EOF) {
				c.logger.Infof("dtls connection closed by remote")
				c.failAllPending(io.EOF)
				c.closeAllTCPStreams(io.EOF)
				c.closeAllUDPSessions(io.EOF)
			} else {
				c.logger.Errorf("dtls read error: %v", err)
				c.failAllPending(err)
				c.closeAllTCPStreams(err)
				c.closeAllUDPSessions(err)
			}
			c.mu.Lock()
			if c.dtlsConn == conn {
				c.dtlsConn = nil
			}
			c.mu.Unlock()
			return
		}
		if n < 20 {
			c.logger.Warnf("dropping short packet: %d bytes", n)
			continue
		}

		header := protocol.PacketHeader{
			Type:      binary.LittleEndian.Uint32(buffer[0:4]),
			ID:        binary.LittleEndian.Uint32(buffer[4:8]),
			Length:    binary.LittleEndian.Uint32(buffer[8:12]),
			Timestamp: int64(binary.LittleEndian.Uint64(buffer[12:20])),
		}

		if header.Length > uint32(n-20) {
			c.logger.Warnf("packet length mismatch: declared=%d actual=%d", header.Length, n-20)
			continue
		}

		payload := make([]byte, header.Length)
		copy(payload, buffer[20:20+header.Length])

		c.processIncoming(&header, payload)
	}
}

func (c *Client) processIncoming(header *protocol.PacketHeader, payload []byte) {
	switch header.Type {
	case protocol.PacketTCP:
		c.handleTCPPacket(header, payload)
		return
	case protocol.PacketUDP:
		c.handleUDPPacket(header, payload)
		return
	}

	if c.dispatchToPending(header, payload) {
		return
	}

	if header.Type == protocol.PacketResponse && header.ID == 0 && string(payload) == "KEEP" {
		c.logger.Debugf("keepalive received")
		return
	}

	if header.Type == protocol.PacketError {
		c.logger.Warnf("unsolicited server error: %s", string(payload))
		return
	}

	c.logger.Warnf("unhandled packet: type=%d id=%d len=%d", header.Type, header.ID, len(payload))
}

func (c *Client) dispatchToPending(header *protocol.PacketHeader, payload []byte) bool {
	c.pendingMu.Lock()
	pr, ok := c.pending[header.ID]
	if ok {
		delete(c.pending, header.ID)
	}
	c.pendingMu.Unlock()

	if !ok {
		return false
	}

	msg := incomingMessage{packetType: header.Type, payload: payload}
	select {
	case pr.ch <- msg:
	default:
		c.logger.Warnf("response channel blocked for request %d", header.ID)
	}
	return true
}

func (c *Client) failAllPending(err error) {
	c.pendingMu.Lock()
	pending := c.pending
	c.pending = make(map[uint32]*pendingRequest)
	c.pendingMu.Unlock()

	for id, pr := range pending {
		select {
		case pr.ch <- incomingMessage{err: err}:
		default:
			c.logger.Warnf("failed to deliver error to request %d", id)
		}
	}
}

func containsUint32(values []uint32, v uint32) bool {
	for _, value := range values {
		if value == v {
			return true
		}
	}
	return false
}
