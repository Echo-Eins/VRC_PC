package server

import (
	"crypto/ecdh"
	"crypto/sha256"
	"fmt"
	"net"
	"time"

	"vpn-relay/config"
	"vpn-relay/protocol"
	"vpn-relay/session"
)

func (s *RelayServer) startMulticastListener() error {
	s.log("🚀 Starting multicast listener...")

	addr, err := net.ResolveUDPAddr("udp", config.MulticastAddr)
	if err != nil {
		s.log(fmt.Sprintf("❌ Failed to resolve multicast address '%s': %v", config.MulticastAddr, err))
		return fmt.Errorf("failed to resolve multicast address: %w", err)
	}
	s.log(fmt.Sprintf("🌐 Multicast address resolved: %v", addr))

	s.log("🔧 Attempting to create multicast UDP listener...")

	conn, err := net.ListenMulticastUDP("udp", nil, addr)
	if err != nil {
		s.log(fmt.Sprintf("❌ Method 1 (ListenMulticastUDP) failed: %v", err))
		s.log("🔧 Trying alternative method (ListenUDP)...")
		conn, err = net.ListenUDP("udp", addr)
		if err != nil {
			s.log(fmt.Sprintf("❌ Method 2 (ListenUDP) also failed: %v", err))
			return fmt.Errorf("failed to listen multicast: %w", err)
		}
		s.log("✅ Alternative method (ListenUDP) succeeded!")
	} else {
		s.log("✅ Standard method (ListenMulticastUDP) succeeded!")
	}

	s.multicastConn = conn

	localAddr := conn.LocalAddr()
	s.log(fmt.Sprintf("🔌 Multicast listener bound to: %v", localAddr))

	s.log(fmt.Sprintf("✅ Multicast listener started on %s", config.MulticastAddr))
	s.log("👂 Starting message handler goroutine...")

	go s.handleMulticastMessages()

	s.log("🎉 Multicast listener setup completed successfully!")
	return nil
}

func (s *RelayServer) handleMulticastMessages() {
	buffer := make([]byte, 1024)
	s.log("Starting multicast message handler...")

	for {
		select {
		case <-s.stopChan:
			s.log("Multicast handler stopping...")
			return
		default:
		}

		s.multicastConn.SetReadDeadline(time.Now().Add(time.Second))
		n, clientAddr, err := s.multicastConn.ReadFromUDP(buffer)

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			s.log(fmt.Sprintf("❌ Multicast read error: %v", err))
			continue
		}

		s.log(fmt.Sprintf("📦 RAW PACKET RECEIVED: %d bytes from %v", n, clientAddr))
		s.log(fmt.Sprintf("📦 Raw data (first 32 bytes): %x", buffer[:min(n, 32)]))
		s.log(fmt.Sprintf("📦 Raw data as string (first 16 bytes): %q", string(buffer[:min(n, 16)])))

		packet, err := protocol.ParseDiscoveryPacket(buffer[:n], time.Now())
		if err != nil {
			s.log(fmt.Sprintf("❌ Invalid discovery packet from %v: %v", clientAddr, err))
			continue
		}

		s.log(fmt.Sprintf("✅ Valid discovery packet from %v (client %x)", clientAddr, packet.ClientID[:4]))
		s.log(fmt.Sprintf("✅ Client public key: %x", packet.PublicKey[:8]))
		s.log(fmt.Sprintf("✅ Timestamp: %d (%s)", packet.Timestamp, time.Unix(packet.Timestamp, 0)))

		s.handleDiscoveryPacket(packet, clientAddr)
	}
}

func (s *RelayServer) handleDiscoveryPacket(packet *protocol.DiscoveryPacket, clientAddr *net.UDPAddr) {
	session := s.getOrCreateSession(packet.ClientID, clientAddr)

	s.log(fmt.Sprintf("Processing discovery packet from client %x at %v", packet.ClientID, clientAddr))

	clientPublicKey, err := ecdh.P256().NewPublicKey(packet.PublicKey[:])
	if err != nil {
		s.log(fmt.Sprintf("Failed to parse client public key: %v", err))
		s.log(fmt.Sprintf("Client key bytes: %x", packet.PublicKey[:]))
		return
	}

	s.log("Successfully parsed client public key")

	sharedSecret, err := s.privateKey.ECDH(clientPublicKey)
	if err != nil {
		s.log(fmt.Sprintf("ECDH key exchange failed: %v", err))
		return
	}

	s.log(fmt.Sprintf("ECDH successful, shared secret length: %d bytes", len(sharedSecret)))

	hasher := sha256.New()
	hasher.Write(sharedSecret)
	hasher.Write([]byte(config.SharedSecret))
	session.SharedKey = hasher.Sum(nil)

	s.log(fmt.Sprintf("Combined key generated, length: %d bytes", len(session.SharedKey)))

	s.sendHandshakeResponse(session, clientAddr)
}

func (s *RelayServer) getOrCreateSession(clientID [16]byte, addr *net.UDPAddr) *session.ClientSession {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()

	sess, exists := s.sessions[clientID]
	if !exists {
		sess = session.NewClientSession(clientID, addr)
		s.sessions[clientID] = sess
		s.log(fmt.Sprintf("New session created for client %x", clientID))
		s.totalConnections++
	} else {
		sess.UpdateRemoteAddr(addr)
	}

	return sess
}

func (s *RelayServer) sendHandshakeResponse(sess *session.ClientSession, clientAddr *net.UDPAddr) {
	response := protocol.HandshakeResponse{
		SessionID: sess.ID,
		DTLSPort:  uint16(config.DTLSPort),
	}

	serverPubBytes := s.publicKey.Bytes()

	if len(serverPubBytes) == 65 && serverPubBytes[0] == 0x04 {
		copy(response.PublicKey[:], serverPubBytes)
		s.log(fmt.Sprintf("Using server uncompressed public key: %x...", serverPubBytes[:8]))
	} else {
		s.log(fmt.Sprintf("ERROR: Server key unexpected format, length %d, prefix %02x",
			len(serverPubBytes), serverPubBytes[0]))
		return
	}

	data := protocol.SerializeHandshakeResponse(response)

	conn, err := net.DialUDP("udp", nil, clientAddr)
	if err != nil {
		s.log(fmt.Sprintf("FAILED to dial client %v for handshake response: %v", clientAddr, err))
		return
	}
	defer conn.Close()

	s.log(fmt.Sprintf("Sending handshake response to %v", clientAddr))

	n, err := conn.Write(data)
	if err != nil {
		s.log(fmt.Sprintf("FAILED to send handshake response: %v", err))
		return
	}

	if n != len(data) {
		s.log(fmt.Sprintf("WARNING: Partial write: sent %d bytes, expected %d", n, len(data)))
		return
	}

	s.log(fmt.Sprintf("SUCCESS: Handshake response sent to %v (%d bytes)", clientAddr, n))
}
