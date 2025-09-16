package client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"vpn-relay/protocol"
)

type UDPSession struct {
	client *Client
	id     uint32
	remote string

	mu        sync.RWMutex
	closed    bool
	err       error
	datagrams chan []byte
}

func newUDPSession(client *Client, id uint32, remote string) *UDPSession {
	return &UDPSession{
		client:    client,
		id:        id,
		remote:    remote,
		datagrams: make(chan []byte, 64),
	}
}

// ID returns the logical identifier assigned to the UDP session.
func (s *UDPSession) ID() uint32 { return s.id }

// RemoteAddr returns the remote UDP address associated with the session.
func (s *UDPSession) RemoteAddr() string { return s.remote }

// Read waits for the next datagram from the remote endpoint.
func (s *UDPSession) Read(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	select {
	case data, ok := <-s.datagrams:
		if !ok {
			s.mu.RLock()
			err := s.err
			s.mu.RUnlock()
			if err == nil {
				err = io.EOF
			}
			return nil, err
		}
		return data, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Send transmits a datagram to the remote endpoint through the relay.
func (s *UDPSession) Send(ctx context.Context, data []byte) error {
	payload := make([]byte, 5+len(data))
	payload[0] = 2
	binary.LittleEndian.PutUint32(payload[1:5], s.id)
	copy(payload[5:], data)

	_, _, err := s.client.sendRequest(ctx, protocol.PacketUDP, payload, []uint32{protocol.PacketResponse})
	return err
}

// Close terminates the UDP association on both the client and server side.
func (s *UDPSession) Close(ctx context.Context) error {
	payload := make([]byte, 5)
	payload[0] = 3
	binary.LittleEndian.PutUint32(payload[1:5], s.id)

	_, _, err := s.client.sendRequest(ctx, protocol.PacketUDP, payload, []uint32{protocol.PacketResponse})
	s.client.removeUDPSession(s.id)
	if err != nil {
		s.closeWithError(err)
		return err
	}
	s.closeWithError(io.EOF)
	return nil
}

func (s *UDPSession) deliver(data []byte) {
	s.mu.RLock()
	closed := s.closed
	s.mu.RUnlock()
	if closed {
		return
	}
	buf := append([]byte(nil), data...)
	select {
	case s.datagrams <- buf:
	default:
		s.client.logger.Warnf("udp session %d backpressure threshold reached; closing", s.id)
		s.closeWithError(fmt.Errorf("udp session %d buffer overflow", s.id))
	}
}

func (s *UDPSession) closeWithError(err error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.err = err
	close(s.datagrams)
	s.mu.Unlock()
}

// DialUDP establishes a UDP relay association to the specified remote address.
func (c *Client) DialUDP(ctx context.Context, targetAddr string) (*UDPSession, error) {
	if targetAddr == "" {
		return nil, errors.New("target address is required")
	}
	if len(targetAddr) > 0xFFFF {
		return nil, fmt.Errorf("target address too long: %d", len(targetAddr))
	}

	connID := c.nextConnectionID()
	session := newUDPSession(c, connID, targetAddr)

	c.udpMu.Lock()
	c.udpSessions[connID] = session
	c.udpMu.Unlock()

	payload := make([]byte, 7+len(targetAddr))
	payload[0] = 1
	binary.LittleEndian.PutUint32(payload[1:5], connID)
	binary.LittleEndian.PutUint16(payload[5:7], uint16(len(targetAddr)))
	copy(payload[7:], []byte(targetAddr))

	_, _, err := c.sendRequest(ctx, protocol.PacketUDP, payload, []uint32{protocol.PacketResponse})
	if err != nil {
		c.udpMu.Lock()
		delete(c.udpSessions, connID)
		c.udpMu.Unlock()
		session.closeWithError(err)
		return nil, err
	}

	return session, nil
}

func (c *Client) removeUDPSession(id uint32) {
	c.udpMu.Lock()
	delete(c.udpSessions, id)
	c.udpMu.Unlock()
}

func (c *Client) handleUDPPacket(header *protocol.PacketHeader, payload []byte) {
	if len(payload) < 5 {
		c.logger.Warnf("invalid udp payload: %d bytes", len(payload))
		return
	}

	command := payload[0]
	connID := binary.LittleEndian.Uint32(payload[1:5])
	data := payload[5:]

	switch command {
	case 4:
		c.udpMu.RLock()
		session, ok := c.udpSessions[connID]
		c.udpMu.RUnlock()
		if !ok {
			c.logger.Warnf("received data for unknown udp connection %d", connID)
			return
		}
		session.deliver(data)
	default:
		c.logger.Warnf("unsupported udp command %d", command)
	}
}

func (c *Client) closeAllUDPSessions(err error) {
	c.udpMu.Lock()
	sessions := c.udpSessions
	c.udpSessions = make(map[uint32]*UDPSession)
	c.udpMu.Unlock()

	for _, session := range sessions {
		session.closeWithError(err)
	}
}
