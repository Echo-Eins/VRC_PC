package session

import (
	"net"
	"sync"
	"time"

	"github.com/pion/dtls/v2"
)

type TCPConnection struct {
	ID         uint32
	LocalConn  net.Conn
	RemoteAddr string
	CreatedAt  time.Time
	LastUsed   time.Time
	Mu         sync.RWMutex
}

type UDPConnection struct {
	ID         uint32
	LocalConn  *net.UDPConn
	RemoteAddr *net.UDPAddr
	CreatedAt  time.Time
	LastUsed   time.Time
	Mu         sync.RWMutex
}

type ClientSession struct {
	ID         [16]byte
	RemoteAddr *net.UDPAddr
	SharedKey  []byte
	DTLSConn   *dtls.Conn

	TCPConns      map[uint32]*TCPConnection
	UDPConns      map[uint32]*UDPConnection
	ConnIDCounter uint32

	BytesIn    uint64
	BytesOut   uint64
	PacketsIn  uint64
	PacketsOut uint64

	LastSeen time.Time
	Mu       sync.RWMutex
}

func NewClientSession(id [16]byte, addr *net.UDPAddr) *ClientSession {
	return &ClientSession{
		ID:         id,
		RemoteAddr: addr,
		TCPConns:   make(map[uint32]*TCPConnection),
		UDPConns:   make(map[uint32]*UDPConnection),
		LastSeen:   time.Now(),
	}
}

func (s *ClientSession) UpdateRemoteAddr(addr *net.UDPAddr) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	s.RemoteAddr = addr
	s.LastSeen = time.Now()
}

func (s *ClientSession) CleanupConnections(now time.Time, timeout time.Duration) {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	for id, conn := range s.TCPConns {
		if now.Sub(conn.LastUsed) > timeout {
			conn.LocalConn.Close()
			delete(s.TCPConns, id)
		}
	}

	for id, conn := range s.UDPConns {
		if now.Sub(conn.LastUsed) > timeout {
			conn.LocalConn.Close()
			delete(s.UDPConns, id)
		}
	}
}

func (s *ClientSession) Cleanup() {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	for _, conn := range s.TCPConns {
		conn.LocalConn.Close()
	}

	for _, conn := range s.UDPConns {
		conn.LocalConn.Close()
	}

	if s.DTLSConn != nil {
		s.DTLSConn.Close()
	}

	s.TCPConns = make(map[uint32]*TCPConnection)
	s.UDPConns = make(map[uint32]*UDPConnection)
}

func (s *ClientSession) SetDTLSConn(conn *dtls.Conn) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	s.DTLSConn = conn
}

func (s *ClientSession) Touch() {
	s.Mu.Lock()
	s.LastSeen = time.Now()
	s.Mu.Unlock()
}
