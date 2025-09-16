package server

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"vpn-relay/config"
	"vpn-relay/protocol"
	"vpn-relay/session"

	"github.com/miekg/dns"
)

func (s *RelayServer) handlePacket(sess *session.ClientSession, header *protocol.PacketHeader, payload []byte) {
	switch header.Type {
	case protocol.PacketHTTP:
		s.handleHTTPRequest(sess, header, payload)
	case protocol.PacketTCP:
		s.handleTCPRequest(sess, header, payload)
	case protocol.PacketDNS:
		s.handleDNSRequest(sess, header, payload)
	case protocol.PacketUDP:
		s.handleUDPRequest(sess, header, payload)
	default:
		s.log(fmt.Sprintf("Unknown packet type: %d", header.Type))
		s.sendErrorResponse(sess, header.ID, "Unknown packet type")
	}
}

func (s *RelayServer) handleHTTPRequest(sess *session.ClientSession, header *protocol.PacketHeader, payload []byte) {
	if len(payload) < 6 {
		s.sendErrorResponse(sess, header.ID, "Invalid HTTP payload")
		return
	}

	addrLen := binary.LittleEndian.Uint16(payload[0:2])
	if len(payload) < int(2+addrLen) {
		s.sendErrorResponse(sess, header.ID, "Invalid address length")
		return
	}

	targetAddr := string(payload[2 : 2+addrLen])
	httpData := payload[2+addrLen:]

	conn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		s.log(fmt.Sprintf("Failed to connect to %s: %v", targetAddr, err))
		s.sendErrorResponse(sess, header.ID, fmt.Sprintf("Connection failed: %v", err))
		return
	}
	defer conn.Close()

	if _, err = conn.Write(httpData); err != nil {
		s.sendErrorResponse(sess, header.ID, fmt.Sprintf("Write failed: %v", err))
		return
	}

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	response := make([]byte, config.MaxPacketSize)
	n, err := conn.Read(response)
	if err != nil && err != io.EOF {
		s.sendErrorResponse(sess, header.ID, fmt.Sprintf("Read failed: %v", err))
		return
	}

	s.sendResponse(sess, header.ID, protocol.PacketResponse, response[:n])
	s.log(fmt.Sprintf("HTTP request to %s completed (%d bytes)", targetAddr, n))
}

func (s *RelayServer) handleTCPRequest(sess *session.ClientSession, header *protocol.PacketHeader, payload []byte) {
	if len(payload) < 6 {
		s.sendErrorResponse(sess, header.ID, "Invalid TCP payload")
		return
	}

	command := payload[0]
	connID := binary.LittleEndian.Uint32(payload[1:5])
	data := payload[5:]

	switch command {
	case 1:
		s.handleTCPConnect(sess, header, connID, data)
	case 2:
		s.handleTCPSend(sess, header, connID, data)
	case 3:
		s.handleTCPClose(sess, header, connID)
	default:
		s.sendErrorResponse(sess, header.ID, "Invalid TCP command")
	}
}

func (s *RelayServer) handleTCPConnect(sess *session.ClientSession, header *protocol.PacketHeader, connID uint32, data []byte) {
	if len(data) < 2 {
		s.sendErrorResponse(sess, header.ID, "Invalid connect data")
		return
	}

	addrLen := binary.LittleEndian.Uint16(data[0:2])
	if len(data) < int(2+addrLen) {
		s.sendErrorResponse(sess, header.ID, "Invalid address")
		return
	}

	targetAddr := string(data[2 : 2+addrLen])

	conn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		s.log(fmt.Sprintf("TCP connect to %s failed: %v", targetAddr, err))
		s.sendErrorResponse(sess, header.ID, fmt.Sprintf("Connect failed: %v", err))
		return
	}

	tcpConn := &session.TCPConnection{
		ID:         connID,
		LocalConn:  conn,
		RemoteAddr: targetAddr,
		CreatedAt:  time.Now(),
		LastUsed:   time.Now(),
	}

	sess.Mu.Lock()
	sess.TCPConns[connID] = tcpConn
	sess.ConnIDCounter = max(sess.ConnIDCounter, connID)
	sess.Mu.Unlock()

	go s.handleTCPRead(sess, tcpConn)

	s.sendResponse(sess, header.ID, protocol.PacketResponse, []byte("connected"))
	s.log(fmt.Sprintf("TCP connection %d established to %s", connID, targetAddr))
}

func (s *RelayServer) handleTCPSend(sess *session.ClientSession, header *protocol.PacketHeader, connID uint32, data []byte) {
	sess.Mu.RLock()
	tcpConn, exists := sess.TCPConns[connID]
	sess.Mu.RUnlock()

	if !exists {
		s.sendErrorResponse(sess, header.ID, "Connection not found")
		return
	}

	tcpConn.Mu.Lock()
	tcpConn.LastUsed = time.Now()
	_, err := tcpConn.LocalConn.Write(data)
	tcpConn.Mu.Unlock()

	if err != nil {
		s.log(fmt.Sprintf("TCP write error on connection %d: %v", connID, err))
		s.sendErrorResponse(sess, header.ID, fmt.Sprintf("Write failed: %v", err))

		sess.Mu.Lock()
		delete(sess.TCPConns, connID)
		sess.Mu.Unlock()
		tcpConn.LocalConn.Close()
		return
	}

	s.sendResponse(sess, header.ID, protocol.PacketResponse, []byte("sent"))
}

func (s *RelayServer) handleTCPRead(sess *session.ClientSession, tcpConn *session.TCPConnection) {
	defer func() {
		tcpConn.LocalConn.Close()
		sess.Mu.Lock()
		delete(sess.TCPConns, tcpConn.ID)
		sess.Mu.Unlock()
	}()

	buffer := make([]byte, 32768)

	for {
		tcpConn.LocalConn.SetReadDeadline(time.Now().Add(config.TCPTimeout))
		n, err := tcpConn.LocalConn.Read(buffer)
		if err != nil {
			if !strings.Contains(err.Error(), "timeout") {
				s.log(fmt.Sprintf("TCP read error on connection %d: %v", tcpConn.ID, err))
			}
			break
		}

		tcpConn.Mu.Lock()
		tcpConn.LastUsed = time.Now()
		tcpConn.Mu.Unlock()

		responseData := make([]byte, 5+n)
		responseData[0] = 4
		binary.LittleEndian.PutUint32(responseData[1:5], tcpConn.ID)
		copy(responseData[5:], buffer[:n])

		s.sendResponse(sess, 0, protocol.PacketTCP, responseData)
	}
}

func (s *RelayServer) handleTCPClose(sess *session.ClientSession, header *protocol.PacketHeader, connID uint32) {
	sess.Mu.Lock()
	tcpConn, exists := sess.TCPConns[connID]
	if exists {
		delete(sess.TCPConns, connID)
	}
	sess.Mu.Unlock()

	if exists {
		tcpConn.LocalConn.Close()
		s.sendResponse(sess, header.ID, protocol.PacketResponse, []byte("closed"))
		s.log(fmt.Sprintf("TCP connection %d closed", connID))
	} else {
		s.sendErrorResponse(sess, header.ID, "Connection not found")
	}
}

func (s *RelayServer) handleDNSRequest(sess *session.ClientSession, header *protocol.PacketHeader, payload []byte) {
	msg := new(dns.Msg)
	if err := msg.Unpack(payload); err != nil {
		s.log(fmt.Sprintf("Invalid DNS query: %v", err))
		s.sendErrorResponse(sess, header.ID, "Invalid DNS query")
		return
	}

	if len(msg.Question) == 0 {
		s.sendErrorResponse(sess, header.ID, "No questions in DNS query")
		return
	}

	question := msg.Question[0]
	s.log(fmt.Sprintf("DNS query for %s (type %d)", question.Name, question.Qtype))

	key := s.getDNSCacheKey(msg)
	if cached := s.getDNSFromCache(key); cached != nil {
		s.log(fmt.Sprintf("Serving DNS response for %s from cache", question.Name))
		s.sendResponse(sess, header.ID, protocol.PacketDNS, cached)
		return
	}

	responseBytes, err := s.resolveDNS(msg)
	if err != nil {
		s.sendErrorResponse(sess, header.ID, fmt.Sprintf("DNS resolution failed: %v", err))
		return
	}

	s.sendResponse(sess, header.ID, protocol.PacketDNS, responseBytes)
}

func (s *RelayServer) resolveDNS(msg *dns.Msg) ([]byte, error) {
	for _, server := range s.GetDNSServers() {
		s.log(fmt.Sprintf("Querying DNS server %s", server))
		response, _, err := s.dnsClient.Exchange(msg, server)
		if err != nil {
			s.log(fmt.Sprintf("DNS query to %s failed: %v", server, err))
			continue
		}

		if response != nil {
			key := s.getDNSCacheKey(msg)
			s.cacheDNSResponse(key, response)
			return response.Pack()
		}
	}

	return nil, fmt.Errorf("all DNS servers failed")
}

func (s *RelayServer) getDNSCacheKey(msg *dns.Msg) string {
	if len(msg.Question) == 0 {
		return ""
	}
	q := msg.Question[0]
	return fmt.Sprintf("%s:%d:%d", strings.ToLower(q.Name), q.Qtype, q.Qclass)
}

func (s *RelayServer) getDNSFromCache(key string) []byte {
	if key == "" {
		return nil
	}

	s.dnsCacheMu.RLock()
	defer s.dnsCacheMu.RUnlock()

	entry, exists := s.dnsCache[key]
	if !exists || time.Now().After(entry.ExpiresAt) {
		return nil
	}

	packed, _ := entry.Response.Pack()
	return packed
}

func (s *RelayServer) cacheDNSResponse(key string, response *dns.Msg) {
	if key == "" || response == nil {
		return
	}

	ttl := uint32(300)

	for _, rr := range response.Answer {
		if rr.Header().Ttl > 0 && rr.Header().Ttl < ttl {
			ttl = rr.Header().Ttl
		}
	}

	if ttl < 60 {
		ttl = 60
	} else if ttl > 3600 {
		ttl = 3600
	}

	entry := &DNSCacheEntry{
		Response:  response.Copy(),
		ExpiresAt: time.Now().Add(time.Duration(ttl) * time.Second),
	}

	s.dnsCacheMu.Lock()
	s.dnsCache[key] = entry
	s.dnsCacheMu.Unlock()
}

func (s *RelayServer) handleUDPRequest(sess *session.ClientSession, header *protocol.PacketHeader, payload []byte) {
	if len(payload) < 6 {
		s.sendErrorResponse(sess, header.ID, "Invalid UDP payload")
		return
	}

	command := payload[0]
	connID := binary.LittleEndian.Uint32(payload[1:5])
	data := payload[5:]

	switch command {
	case 1:
		s.handleUDPConnect(sess, header, connID, data)
	case 2:
		s.handleUDPSend(sess, header, connID, data)
	case 3:
		s.handleUDPClose(sess, header, connID)
	default:
		s.sendErrorResponse(sess, header.ID, "Invalid UDP command")
	}
}

func (s *RelayServer) handleUDPConnect(sess *session.ClientSession, header *protocol.PacketHeader, connID uint32, data []byte) {
	if len(data) < 2 {
		s.sendErrorResponse(sess, header.ID, "Invalid UDP connect data")
		return
	}

	addrLen := binary.LittleEndian.Uint16(data[0:2])
	if len(data) < int(2+addrLen) {
		s.sendErrorResponse(sess, header.ID, "Invalid UDP address")
		return
	}

	targetAddr := string(data[2 : 2+addrLen])

	udpAddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		s.log(fmt.Sprintf("Failed to resolve UDP address %s: %v", targetAddr, err))
		s.sendErrorResponse(sess, header.ID, fmt.Sprintf("Address resolution failed: %v", err))
		return
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		s.log(fmt.Sprintf("Failed to create UDP connection to %s: %v", targetAddr, err))
		s.sendErrorResponse(sess, header.ID, fmt.Sprintf("UDP connection failed: %v", err))
		return
	}

	udpConn := &session.UDPConnection{
		ID:         connID,
		LocalConn:  conn,
		RemoteAddr: udpAddr,
		CreatedAt:  time.Now(),
		LastUsed:   time.Now(),
	}

	sess.Mu.Lock()
	sess.UDPConns[connID] = udpConn
	sess.ConnIDCounter = max(sess.ConnIDCounter, connID)
	sess.Mu.Unlock()

	go s.handleUDPRead(sess, udpConn)

	s.sendResponse(sess, header.ID, protocol.PacketResponse, []byte("connected"))
	s.log(fmt.Sprintf("UDP connection %d established to %s", connID, targetAddr))
}

func (s *RelayServer) handleUDPSend(sess *session.ClientSession, header *protocol.PacketHeader, connID uint32, data []byte) {
	sess.Mu.RLock()
	udpConn, exists := sess.UDPConns[connID]
	sess.Mu.RUnlock()

	if !exists {
		s.sendErrorResponse(sess, header.ID, "UDP connection not found")
		return
	}

	udpConn.Mu.Lock()
	udpConn.LastUsed = time.Now()
	_, err := udpConn.LocalConn.Write(data)
	udpConn.Mu.Unlock()

	if err != nil {
		s.log(fmt.Sprintf("UDP write error on connection %d: %v", connID, err))
		s.sendErrorResponse(sess, header.ID, fmt.Sprintf("UDP write failed: %v", err))

		sess.Mu.Lock()
		delete(sess.UDPConns, connID)
		sess.Mu.Unlock()
		udpConn.LocalConn.Close()
		return
	}

	s.sendResponse(sess, header.ID, protocol.PacketResponse, []byte("sent"))
}

func (s *RelayServer) handleUDPRead(sess *session.ClientSession, udpConn *session.UDPConnection) {
	defer func() {
		udpConn.LocalConn.Close()
		sess.Mu.Lock()
		delete(sess.UDPConns, udpConn.ID)
		sess.Mu.Unlock()
	}()

	buffer := make([]byte, 65507)

	for {
		udpConn.LocalConn.SetReadDeadline(time.Now().Add(config.TCPTimeout))
		n, err := udpConn.LocalConn.Read(buffer)
		if err != nil {
			if !strings.Contains(err.Error(), "timeout") {
				s.log(fmt.Sprintf("UDP read error on connection %d: %v", udpConn.ID, err))
			}
			break
		}

		udpConn.Mu.Lock()
		udpConn.LastUsed = time.Now()
		udpConn.Mu.Unlock()

		responseData := make([]byte, 5+n)
		responseData[0] = 4
		binary.LittleEndian.PutUint32(responseData[1:5], udpConn.ID)
		copy(responseData[5:], buffer[:n])

		s.sendResponse(sess, 0, protocol.PacketUDP, responseData)
	}
}

func (s *RelayServer) handleUDPClose(sess *session.ClientSession, header *protocol.PacketHeader, connID uint32) {
	sess.Mu.Lock()
	udpConn, exists := sess.UDPConns[connID]
	if exists {
		delete(sess.UDPConns, connID)
	}
	sess.Mu.Unlock()

	if exists {
		udpConn.LocalConn.Close()
		s.sendResponse(sess, header.ID, protocol.PacketResponse, []byte("closed"))
		s.log(fmt.Sprintf("UDP connection %d closed", connID))
	} else {
		s.sendErrorResponse(sess, header.ID, "UDP connection not found")
	}
}

func (s *RelayServer) sendResponse(sess *session.ClientSession, requestID uint32, packetType uint32, data []byte) {
	sess.Mu.RLock()
	conn := sess.DTLSConn
	sess.Mu.RUnlock()
	if conn == nil {
		return
	}

	header := protocol.PacketHeader{
		Type:      packetType,
		ID:        requestID,
		Length:    uint32(len(data)),
		Timestamp: time.Now().Unix(),
	}

	packet := make([]byte, 20+len(data))
	binary.LittleEndian.PutUint32(packet[0:4], header.Type)
	binary.LittleEndian.PutUint32(packet[4:8], header.ID)
	binary.LittleEndian.PutUint32(packet[8:12], header.Length)
	binary.LittleEndian.PutUint64(packet[12:20], uint64(header.Timestamp))
	copy(packet[20:], data)

	sess.Mu.Lock()
	if sess.DTLSConn != nil {
		if _, err := sess.DTLSConn.Write(packet); err != nil {
			sess.Mu.Unlock()
			s.log(fmt.Sprintf("Failed to send response: %v", err))
			return
		}
		sess.PacketsOut++
		sess.BytesOut += uint64(len(packet))
	}
	sess.Mu.Unlock()

	s.totalBytes += uint64(len(packet))
}

func (s *RelayServer) sendErrorResponse(sess *session.ClientSession, requestID uint32, errorMsg string) {
	s.sendResponse(sess, requestID, protocol.PacketError, []byte(errorMsg))
}
