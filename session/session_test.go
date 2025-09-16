package session

import (
	"net"
	"testing"
	"time"
)

func TestNewClientSession(t *testing.T) {
	var id [16]byte
	id[0] = 1
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}

	sess := NewClientSession(id, addr)
	if sess.RemoteAddr.String() != addr.String() {
		t.Fatalf("unexpected remote address: %v", sess.RemoteAddr)
	}
	if len(sess.TCPConns) != 0 || len(sess.UDPConns) != 0 {
		t.Fatalf("expected empty connection maps")
	}
}

func TestCleanupConnections(t *testing.T) {
	var id [16]byte
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	sess := NewClientSession(id, addr)

	tcpConn, tcpPeer := net.Pipe()
	defer tcpPeer.Close()

	sess.TCPConns[1] = &TCPConnection{
		ID:        1,
		LocalConn: tcpConn,
		LastUsed:  time.Now().Add(-2 * time.Second),
	}

	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatalf("failed to create udp listener: %v", err)
	}
	defer udpConn.Close()
	sess.UDPConns[1] = &UDPConnection{
		ID:        1,
		LocalConn: udpConn,
		LastUsed:  time.Now().Add(-2 * time.Second),
	}

	sess.CleanupConnections(time.Now(), time.Second)

	if len(sess.TCPConns) != 0 {
		t.Fatalf("expected TCP connections to be cleaned up")
	}
	if len(sess.UDPConns) != 0 {
		t.Fatalf("expected UDP connections to be cleaned up")
	}
}

func TestCleanup(t *testing.T) {
	var id [16]byte
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	sess := NewClientSession(id, addr)

	tcpConn, tcpPeer := net.Pipe()
	defer tcpPeer.Close()
	sess.TCPConns[1] = &TCPConnection{ID: 1, LocalConn: tcpConn}

	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatalf("failed to create udp listener: %v", err)
	}
	defer udpConn.Close()
	sess.UDPConns[1] = &UDPConnection{ID: 1, LocalConn: udpConn}

	sess.Cleanup()

	if len(sess.TCPConns) != 0 || len(sess.UDPConns) != 0 {
		t.Fatalf("expected connections to be cleared")
	}
}
