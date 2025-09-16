package server

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"vpn-relay/config"
	"vpn-relay/protocol"
	"vpn-relay/session"

	"github.com/pion/dtls/v2"
)

func (s *RelayServer) startDTLSServer() error {
	cfg := &dtls.Config{
		PSK: func(hint []byte) ([]byte, error) {
			return []byte(config.SharedSecret), nil
		},
		PSKIdentityHint: []byte("vpn-relay"),
		CipherSuites:    []dtls.CipherSuiteID{dtls.TLS_PSK_WITH_AES_128_GCM_SHA256},
	}

	addr, err := net.ResolveUDPAddr("udp", config.DTLSListenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve DTLS address: %w", err)
	}

	listener, err := dtls.Listen("udp", addr, cfg)
	if err != nil {
		return fmt.Errorf("failed to start DTLS listener: %w", err)
	}

	s.dtlsListener = listener
	s.log("DTLS server started on port 8889")

	go s.handleDTLSConnections()
	return nil
}

func (s *RelayServer) handleDTLSConnections() {
	for {
		select {
		case <-s.stopChan:
			return
		default:
		}

		conn, err := s.dtlsListener.Accept()
		if err != nil {
			s.log(fmt.Sprintf("DTLS accept error: %v", err))
			continue
		}

		dtlsConn := conn.(*dtls.Conn)
		s.log(fmt.Sprintf("DTLS connection established with %v", dtlsConn.RemoteAddr()))

		go s.handleClientConnection(dtlsConn)
	}
}

func (s *RelayServer) handleClientConnection(conn *dtls.Conn) {
	defer func() {
		s.log(fmt.Sprintf("🚪 Closing DTLS connection with %v", conn.RemoteAddr()))
		conn.Close()
	}()

	s.log(fmt.Sprintf("🔗 New DTLS connection from %v", conn.RemoteAddr()))
	s.log(fmt.Sprintf("🔍 Local DTLS address: %v", conn.LocalAddr()))

	sess := s.findSessionByDTLSConn(conn)
	if sess == nil {
		s.log(fmt.Sprintf("❌ Could not find session for DTLS connection from %v", conn.RemoteAddr()))
		return
	}

	sess.SetDTLSConn(conn)
	s.log("✅ DTLS connection bound to session")

	s.log("🧪 Testing DTLS connection...")
	buffer := make([]byte, 1024)

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buffer)

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			s.log("⏰ No initial data from client (normal)")
		} else {
			s.log(fmt.Sprintf("❌ Initial read error: %v", err))
			return
		}
	} else {
		s.log(fmt.Sprintf("📨 Received initial data: %d bytes", n))
		if string(buffer[:n]) == "PING" {
			s.log("🏓 Received PING, sending PONG...")
			conn.Write([]byte("PONG"))
		}
	}

	s.log("🔄 Starting main DTLS message loop...")

	keepaliveStop := make(chan struct{})
	go s.keepaliveLoop(sess, keepaliveStop)
	defer close(keepaliveStop)

	buffer = make([]byte, config.MaxPacketSize)

	for {
		conn.SetReadDeadline(time.Now().Add(config.TCPTimeout))
		n, err := conn.Read(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			s.log(fmt.Sprintf("DTLS read error: %v", err))
			return
		}

		if n < 20 {
			s.log(fmt.Sprintf("Invalid packet: too short (%d bytes)", n))
			continue
		}

		header := &protocol.PacketHeader{
			Type:      binary.LittleEndian.Uint32(buffer[0:4]),
			ID:        binary.LittleEndian.Uint32(buffer[4:8]),
			Length:    binary.LittleEndian.Uint32(buffer[8:12]),
			Timestamp: int64(binary.LittleEndian.Uint64(buffer[12:20])),
		}

		payload := make([]byte, header.Length)
		copy(payload, buffer[20:20+header.Length])

		sess.Mu.Lock()
		sess.LastSeen = time.Now()
		sess.PacketsIn++
		sess.BytesIn += uint64(n)
		sess.Mu.Unlock()

		s.handlePacket(sess, header, payload)
	}
}

func (s *RelayServer) keepaliveLoop(sess *session.ClientSession, stop <-chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			keepaliveHeader := protocol.PacketHeader{
				Type:      protocol.PacketResponse,
				ID:        0,
				Length:    4,
				Timestamp: time.Now().Unix(),
			}

			packet := make([]byte, 24)
			binary.LittleEndian.PutUint32(packet[0:4], keepaliveHeader.Type)
			binary.LittleEndian.PutUint32(packet[4:8], keepaliveHeader.ID)
			binary.LittleEndian.PutUint32(packet[8:12], keepaliveHeader.Length)
			binary.LittleEndian.PutUint64(packet[12:20], uint64(keepaliveHeader.Timestamp))
			copy(packet[20:24], []byte("KEEP"))

			sess.Mu.Lock()
			if sess.DTLSConn != nil {
				if _, err := sess.DTLSConn.Write(packet); err != nil {
					sess.Mu.Unlock()
					s.log(fmt.Sprintf("❌ Keepalive send failed: %v", err))
					return
				}
				s.log("💓 Keepalive sent to client")
			}
			sess.Mu.Unlock()
		}
	}
}

func (s *RelayServer) findSessionByDTLSConn(conn *dtls.Conn) *session.ClientSession {
	remoteAddr := conn.RemoteAddr().String()

	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()

	for _, sess := range s.sessions {
		if sess.RemoteAddr != nil && sess.RemoteAddr.String() == remoteAddr {
			return sess
		}
	}

	s.log("❌ No matching session found")
	return nil
}
