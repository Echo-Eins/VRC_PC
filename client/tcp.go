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

type TCPStream struct {
	client *Client
	id     uint32
	remote string

	mu       sync.RWMutex
	closed   bool
	err      error
	messages chan []byte
}

func newTCPStream(client *Client, id uint32, remote string) *TCPStream {
	return &TCPStream{
		client:   client,
		id:       id,
		remote:   remote,
		messages: make(chan []byte, 32),
	}
}

// ID returns the logical identifier of the TCP stream.
func (s *TCPStream) ID() uint32 { return s.id }

// RemoteAddr returns the remote TCP address associated with the stream.
func (s *TCPStream) RemoteAddr() string { return s.remote }

// Read returns the next payload received from the remote endpoint. When the
// stream is closed it returns the underlying error (io.EOF when closed
// gracefully).
func (s *TCPStream) Read(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	select {
	case data, ok := <-s.messages:
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

// Write transmits data to the remote endpoint via the relay.
func (s *TCPStream) Write(ctx context.Context, data []byte) error {
	if len(data) == 0 {
		return nil
	}

	payload := make([]byte, 5+len(data))
	payload[0] = 2
	binary.LittleEndian.PutUint32(payload[1:5], s.id)
	copy(payload[5:], data)

	_, _, err := s.client.sendRequest(ctx, protocol.PacketTCP, payload, []uint32{protocol.PacketResponse})
	return err
}

// Close tears down the stream on the server and releases local resources.
func (s *TCPStream) Close(ctx context.Context) error {
	payload := make([]byte, 5)
	payload[0] = 3
	binary.LittleEndian.PutUint32(payload[1:5], s.id)

	_, _, err := s.client.sendRequest(ctx, protocol.PacketTCP, payload, []uint32{protocol.PacketResponse})
	s.client.removeTCPStream(s.id)
	if err != nil {
		s.closeWithError(err)
		return err
	}
	s.closeWithError(io.EOF)
	return nil
}

func (s *TCPStream) deliverData(data []byte) {
	s.mu.RLock()
	closed := s.closed
	s.mu.RUnlock()
	if closed {
		return
	}

	buf := append([]byte(nil), data...)
	select {
	case s.messages <- buf:
	default:
		s.client.logger.Warnf("tcp stream %d backpressure threshold reached; closing", s.id)
		s.closeWithError(fmt.Errorf("tcp stream %d buffer overflow", s.id))
	}
}

func (s *TCPStream) closeWithError(err error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.err = err
	close(s.messages)
	s.mu.Unlock()
}

// DialTCP establishes a TCP relay connection to the given target.
func (c *Client) DialTCP(ctx context.Context, targetAddr string) (*TCPStream, error) {
	if targetAddr == "" {
		return nil, errors.New("target address is required")
	}
	if len(targetAddr) > 0xFFFF {
		return nil, fmt.Errorf("target address too long: %d", len(targetAddr))
	}

	connID := c.nextConnectionID()
	stream := newTCPStream(c, connID, targetAddr)

	c.tcpMu.Lock()
	c.tcpStreams[connID] = stream
	c.tcpMu.Unlock()

	payload := make([]byte, 7+len(targetAddr))
	payload[0] = 1
	binary.LittleEndian.PutUint32(payload[1:5], connID)
	binary.LittleEndian.PutUint16(payload[5:7], uint16(len(targetAddr)))
	copy(payload[7:], []byte(targetAddr))

	_, _, err := c.sendRequest(ctx, protocol.PacketTCP, payload, []uint32{protocol.PacketResponse})
	if err != nil {
		c.tcpMu.Lock()
		delete(c.tcpStreams, connID)
		c.tcpMu.Unlock()
		stream.closeWithError(err)
		return nil, err
	}

	return stream, nil
}

func (c *Client) removeTCPStream(id uint32) {
	c.tcpMu.Lock()
	delete(c.tcpStreams, id)
	c.tcpMu.Unlock()
}

func (c *Client) handleTCPPacket(header *protocol.PacketHeader, payload []byte) {
	if len(payload) < 5 {
		c.logger.Warnf("invalid tcp payload: %d bytes", len(payload))
		return
	}

	command := payload[0]
	connID := binary.LittleEndian.Uint32(payload[1:5])
	data := payload[5:]

	switch command {
	case 4:
		c.tcpMu.RLock()
		stream, ok := c.tcpStreams[connID]
		c.tcpMu.RUnlock()
		if !ok {
			c.logger.Warnf("received data for unknown tcp connection %d", connID)
			return
		}
		stream.deliverData(data)
	default:
		c.logger.Warnf("unsupported tcp command %d", command)
	}
}

func (c *Client) closeAllTCPStreams(err error) {
	c.tcpMu.Lock()
	streams := c.tcpStreams
	c.tcpStreams = make(map[uint32]*TCPStream)
	c.tcpMu.Unlock()

	for _, stream := range streams {
		stream.closeWithError(err)
	}
}
