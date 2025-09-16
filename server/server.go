package server

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"vpn-relay/config"
	"vpn-relay/session"

	"github.com/miekg/dns"
)

type DNSCacheEntry struct {
	Response  *dns.Msg
	ExpiresAt time.Time
}

type SessionSummary struct {
	ID         string
	RemoteAddr string
	TCPCount   int
	UDPCount   int
	BytesIn    uint64
	BytesOut   uint64
}

type Stats struct {
	Uptime              time.Duration
	ActiveClients       int
	TotalConnections    uint64
	TotalBytes          uint64
	TotalBytesIn        uint64
	TotalBytesOut       uint64
	TotalPacketsIn      uint64
	TotalPacketsOut     uint64
	TotalTCPConnections int
	TotalUDPConnections int
	DNSCacheEntries     int
	Running             bool
}

type RelayServer struct {
	multicastConn *net.UDPConn
	dtlsListener  net.Listener
	sessions      map[[16]byte]*session.ClientSession
	sessionsMu    sync.RWMutex

	privateKey *ecdh.PrivateKey
	publicKey  *ecdh.PublicKey

	dnsServers []string
	dnsCache   map[string]*DNSCacheEntry
	dnsCacheMu sync.RWMutex
	dnsClient  *dns.Client

	stopChan chan struct{}
	logChan  chan string

	totalConnections uint64
	totalBytes       uint64
	startTime        time.Time
}

func NewRelayServer() (*RelayServer, error) {
	curve := ecdh.P256()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDH key: %w", err)
	}

	publicKeyBytes := privateKey.PublicKey().Bytes()
	log.Printf("Server public key format: length=%d, prefix=%02x", len(publicKeyBytes), publicKeyBytes[0])

	if len(publicKeyBytes) != 65 || publicKeyBytes[0] != 0x04 {
		return nil, fmt.Errorf("unexpected public key format: expected 65 bytes with 0x04 prefix, got %d bytes with %02x prefix",
			len(publicKeyBytes), publicKeyBytes[0])
	}

	dnsClient := &dns.Client{
		Net:     "udp",
		Timeout: config.DNSTimeout,
	}

	dnsServers := config.GetSystemDNSServers()

	server := &RelayServer{
		sessions:   make(map[[16]byte]*session.ClientSession),
		privateKey: privateKey,
		publicKey:  privateKey.PublicKey(),
		stopChan:   make(chan struct{}),
		logChan:    make(chan string, 1000),
		dnsServers: dnsServers,
		dnsCache:   make(map[string]*DNSCacheEntry),
		dnsClient:  dnsClient,
		startTime:  time.Now(),
	}

	go server.cleanupRoutine()

	return server, nil
}

func (s *RelayServer) Logs() <-chan string {
	return s.logChan
}

func (s *RelayServer) Logf(format string, args ...interface{}) {
	s.log(fmt.Sprintf(format, args...))
}

func (s *RelayServer) log(message string) {
	timestamp := time.Now().Format("15:04:05")
	logMessage := fmt.Sprintf("[%s] %s", timestamp, message)

	select {
	case s.logChan <- logMessage:
	default:
	}

	log.Println(message)
}

func (s *RelayServer) cleanupRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			s.cleanupSessions()
			s.cleanupDNSCache()
		}
	}
}

func (s *RelayServer) cleanupSessions() {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()

	now := time.Now()
	for id, sess := range s.sessions {
		if now.Sub(sess.LastSeen) > config.SessionTimeout {
			s.log(fmt.Sprintf("Cleaning up expired session %x", id))
			sess.Cleanup()
			delete(s.sessions, id)
		} else {
			sess.CleanupConnections(now, config.TCPTimeout)
		}
	}
}

func (s *RelayServer) cleanupDNSCache() {
	s.dnsCacheMu.Lock()
	defer s.dnsCacheMu.Unlock()

	now := time.Now()
	for key, entry := range s.dnsCache {
		if now.After(entry.ExpiresAt) {
			delete(s.dnsCache, key)
		}
	}
}

func (s *RelayServer) Start() error {
	s.log("Starting VPN Relay Server...")

	if err := s.startMulticastListener(); err != nil {
		s.log(fmt.Sprintf("Failed to start multicast listener: %v", err))
		return err
	}

	if err := s.startDTLSServer(); err != nil {
		s.log(fmt.Sprintf("Failed to start DTLS server: %v", err))
		if s.multicastConn != nil {
			s.multicastConn.Close()
			s.multicastConn = nil
		}
		return err
	}

	s.log("VPN Relay Server started successfully")
	s.log(fmt.Sprintf("Multicast discovery: %s", config.MulticastAddr))
	s.log(fmt.Sprintf("DTLS server: port %d", config.DTLSPort))
	s.log(fmt.Sprintf("DNS servers: %s", strings.Join(s.GetDNSServers(), ", ")))
	return nil
}

func (s *RelayServer) Stop() {
	s.log("Stopping VPN Relay Server...")

	select {
	case <-s.stopChan:
	default:
		close(s.stopChan)
	}

	if s.multicastConn != nil {
		s.multicastConn.Close()
		s.multicastConn = nil
	}

	if s.dtlsListener != nil {
		s.dtlsListener.Close()
		s.dtlsListener = nil
	}

	s.sessionsMu.Lock()
	for _, sess := range s.sessions {
		sess.Cleanup()
	}
	s.sessions = make(map[[16]byte]*session.ClientSession)
	s.sessionsMu.Unlock()

	s.dnsCacheMu.Lock()
	s.dnsCache = make(map[string]*DNSCacheEntry)
	s.dnsCacheMu.Unlock()

	s.stopChan = make(chan struct{})

	s.log("VPN Relay Server stopped")
}

func (s *RelayServer) GetDNSServers() []string {
	s.dnsCacheMu.RLock()
	defer s.dnsCacheMu.RUnlock()
	return append([]string(nil), s.dnsServers...)
}

func (s *RelayServer) SetDNSServers(servers []string) {
	cleaned := make([]string, 0, len(servers))
	for _, server := range servers {
		server = strings.TrimSpace(server)
		if server != "" {
			cleaned = append(cleaned, server)
		}
	}

	if len(cleaned) == 0 {
		cleaned = config.FallbackDNSServers()
	}

	s.dnsCacheMu.Lock()
	s.dnsServers = cleaned
	s.dnsCacheMu.Unlock()
}

func (s *RelayServer) ClearDNSCache() int {
	s.dnsCacheMu.Lock()
	oldSize := len(s.dnsCache)
	s.dnsCache = make(map[string]*DNSCacheEntry)
	s.dnsCacheMu.Unlock()
	return oldSize
}

func (s *RelayServer) Stats() Stats {
	s.sessionsMu.RLock()
	activeClients := len(s.sessions)

	var totalBytesIn, totalBytesOut, totalPacketsIn, totalPacketsOut uint64
	var totalTCP, totalUDP int
	for _, sess := range s.sessions {
		sess.Mu.RLock()
		totalBytesIn += sess.BytesIn
		totalBytesOut += sess.BytesOut
		totalPacketsIn += sess.PacketsIn
		totalPacketsOut += sess.PacketsOut
		totalTCP += len(sess.TCPConns)
		totalUDP += len(sess.UDPConns)
		sess.Mu.RUnlock()
	}
	s.sessionsMu.RUnlock()

	s.dnsCacheMu.RLock()
	dnsEntries := len(s.dnsCache)
	s.dnsCacheMu.RUnlock()

	running := s.multicastConn != nil && s.dtlsListener != nil

	return Stats{
		Uptime:              time.Since(s.startTime),
		ActiveClients:       activeClients,
		TotalConnections:    s.totalConnections,
		TotalBytes:          s.totalBytes,
		TotalBytesIn:        totalBytesIn,
		TotalBytesOut:       totalBytesOut,
		TotalPacketsIn:      totalPacketsIn,
		TotalPacketsOut:     totalPacketsOut,
		TotalTCPConnections: totalTCP,
		TotalUDPConnections: totalUDP,
		DNSCacheEntries:     dnsEntries,
		Running:             running,
	}
}

func (s *RelayServer) SessionSummaries() []SessionSummary {
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()

	summaries := make([]SessionSummary, 0, len(s.sessions))
	for id, sess := range s.sessions {
		sess.Mu.RLock()
		summary := SessionSummary{
			ID:       fmt.Sprintf("%x", id[:4]),
			TCPCount: len(sess.TCPConns),
			UDPCount: len(sess.UDPConns),
			BytesIn:  sess.BytesIn,
			BytesOut: sess.BytesOut,
		}
		if sess.RemoteAddr != nil {
			summary.RemoteAddr = sess.RemoteAddr.String()
		}
		sess.Mu.RUnlock()
		summaries = append(summaries, summary)
	}
	return summaries
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}
