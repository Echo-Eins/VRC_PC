package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/miekg/dns"
	"github.com/pion/dtls/v2"
)

const (
	MULTICAST_ADDR = "224.0.0.251:8888"
	MAGIC_BYTES    = "VPNR"
	SHARED_SECRET  = "your-shared-secret-here" // В продакшене из конфига

	// Типы пакетов
	PACKET_HTTP     = 1
	PACKET_TCP      = 2
	PACKET_DNS      = 3
	PACKET_UDP      = 4
	PACKET_RESPONSE = 100
	PACKET_ERROR    = 200

	// Ограничения
	MAX_PACKET_SIZE = 65536
	SESSION_TIMEOUT = 300 // 5 минут
	DNS_TIMEOUT     = 5   // 5 секунд
	TCP_TIMEOUT     = 30  // 30 секунд
)

// Структуры протокола
type DiscoveryPacket struct {
	Magic     [4]byte
	ClientID  [16]byte
	PublicKey [32]byte
	Timestamp int64
}

type HandshakeResponse struct {
	SessionID [16]byte
	PublicKey [32]byte
	DTLSPort  uint16
}

// Заголовок пакета данных
type PacketHeader struct {
	Type      uint32
	ID        uint32 // Уникальный ID для сопоставления запроса/ответа
	Length    uint32
	Timestamp int64
}

// TCP соединение
type TCPConnection struct {
	ID         uint32
	LocalConn  net.Conn
	RemoteAddr string
	CreatedAt  time.Time
	LastUsed   time.Time
	mu         sync.RWMutex
}

// UDP соединение
type UDPConnection struct {
	ID         uint32
	LocalConn  *net.UDPConn
	RemoteAddr *net.UDPAddr
	CreatedAt  time.Time
	LastUsed   time.Time
	mu         sync.RWMutex
}

// Активная сессия клиента
type ClientSession struct {
	ID         [16]byte
	RemoteAddr *net.UDPAddr
	SharedKey  []byte
	DTLSConn   *dtls.Conn

	// Активные соединения
	TCPConns      map[uint32]*TCPConnection
	UDPConns      map[uint32]*UDPConnection
	ConnIDCounter uint32

	// Статистика
	BytesIn    uint64
	BytesOut   uint64
	PacketsIn  uint64
	PacketsOut uint64

	LastSeen time.Time
	mu       sync.RWMutex
}

// DNS кэш
type DNSCacheEntry struct {
	Response  *dns.Msg
	ExpiresAt time.Time
}

// Основной сервер
type RelayServer struct {
	multicastConn *net.UDPConn
	dtlsListener  net.Listener
	sessions      map[[16]byte]*ClientSession
	sessionsMu    sync.RWMutex

	// ECDH ключи сервера
	privateKey *ecdh.PrivateKey
	publicKey  *ecdh.PublicKey

	// DNS настройки и кэш
	dnsServers []string
	dnsCache   map[string]*DNSCacheEntry
	dnsCacheMu sync.RWMutex
	dnsClient  *dns.Client

	// GUI элементы
	statusLabel *widget.Label
	clientsList *widget.List
	logText     *widget.Entry
	statsLabel  *widget.Label

	// Каналы управления
	stopChan chan struct{}
	logChan  chan string

	// Статистика
	totalConnections uint64
	totalBytes       uint64
	startTime        time.Time
}

func NewRelayServer() (*RelayServer, error) {
	// Генерируем ECDH ключи
	curve := ecdh.P256()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDH key: %v", err)
	}

	// Инициализируем DNS клиент
	dnsClient := &dns.Client{
		Net:     "udp",
		Timeout: DNS_TIMEOUT * time.Second,
	}

	// Получаем системные DNS серверы
	dnsServers := getSystemDNSServers()
	if len(dnsServers) == 0 {
		dnsServers = []string{"8.8.8.8:53", "1.1.1.1:53"} // Fallback
	}

	server := &RelayServer{
		sessions:   make(map[[16]byte]*ClientSession),
		privateKey: privateKey,
		publicKey:  privateKey.PublicKey(),
		stopChan:   make(chan struct{}),
		logChan:    make(chan string, 1000),
		dnsServers: dnsServers,
		dnsCache:   make(map[string]*DNSCacheEntry),
		dnsClient:  dnsClient,
		startTime:  time.Now(),
	}

	// Запускаем cleanup горутину
	go server.cleanupRoutine()

	return server, nil
}

// Получение системных DNS серверов
func getSystemDNSServers() []string {
	var servers []string

	// Читаем /etc/resolv.conf на Unix системах
	// На Windows можно использовать системные вызовы, но для простоты используем fallback
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err == nil {
		for _, server := range config.Servers {
			servers = append(servers, net.JoinHostPort(server, "53"))
		}
	}

	return servers
}

// Cleanup routine для старых соединений и кэша
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

// Очистка старых сессий
func (s *RelayServer) cleanupSessions() {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()

	now := time.Now()
	for id, session := range s.sessions {
		if now.Sub(session.LastSeen) > SESSION_TIMEOUT*time.Second {
			s.log(fmt.Sprintf("Cleaning up expired session %x", id))
			session.cleanup()
			delete(s.sessions, id)
		} else {
			// Очищаем старые соединения в активных сессиях
			session.cleanupConnections(now)
		}
	}
}

// Очистка DNS кэша
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

// Очистка соединений сессии
func (session *ClientSession) cleanupConnections(now time.Time) {
	session.mu.Lock()
	defer session.mu.Unlock()

	// Очищаем TCP соединения
	for id, conn := range session.TCPConns {
		if now.Sub(conn.LastUsed) > TCP_TIMEOUT*time.Second {
			conn.LocalConn.Close()
			delete(session.TCPConns, id)
		}
	}

	// Очищаем UDP соединения
	for id, conn := range session.UDPConns {
		if now.Sub(conn.LastUsed) > TCP_TIMEOUT*time.Second {
			conn.LocalConn.Close()
			delete(session.UDPConns, id)
		}
	}
}

// Очистка ресурсов сессии
func (session *ClientSession) cleanup() {
	session.mu.Lock()
	defer session.mu.Unlock()

	// Закрываем все TCP соединения
	for _, conn := range session.TCPConns {
		conn.LocalConn.Close()
	}

	// Закрываем все UDP соединения
	for _, conn := range session.UDPConns {
		conn.LocalConn.Close()
	}

	// Закрываем DTLS соединение
	if session.DTLSConn != nil {
		session.DTLSConn.Close()
	}
}

// Запуск multicast listener
func (s *RelayServer) startMulticastListener() error {
	addr, err := net.ResolveUDPAddr("udp", MULTICAST_ADDR)
	if err != nil {
		return fmt.Errorf("failed to resolve multicast address: %v", err)
	}

	conn, err := net.ListenMulticastUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("failed to listen multicast: %v", err)
	}

	s.multicastConn = conn
	s.log("Multicast listener started on " + MULTICAST_ADDR)

	go s.handleMulticastMessages()
	return nil
}

// Обработка multicast сообщений
func (s *RelayServer) handleMulticastMessages() {
	buffer := make([]byte, 1024)

	for {
		select {
		case <-s.stopChan:
			return
		default:
		}

		s.multicastConn.SetReadDeadline(time.Now().Add(time.Second))
		n, clientAddr, err := s.multicastConn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			s.log(fmt.Sprintf("Multicast read error: %v", err))
			continue
		}

		if n < 56 { // Минимальный размер DiscoveryPacket
			continue
		}

		var packet DiscoveryPacket
		if err := s.parseDiscoveryPacket(buffer[:n], &packet); err != nil {
			s.log(fmt.Sprintf("Invalid discovery packet from %v: %v", clientAddr, err))
			continue
		}

		s.log(fmt.Sprintf("Discovery packet from %v", clientAddr))
		s.handleDiscoveryPacket(&packet, clientAddr)
	}
}

// Парсинг discovery пакета
func (s *RelayServer) parseDiscoveryPacket(data []byte, packet *DiscoveryPacket) error {
	if len(data) < 56 {
		return fmt.Errorf("packet too short")
	}

	copy(packet.Magic[:], data[0:4])
	if string(packet.Magic[:]) != MAGIC_BYTES {
		return fmt.Errorf("invalid magic bytes")
	}

	copy(packet.ClientID[:], data[4:20])
	copy(packet.PublicKey[:], data[20:52])
	packet.Timestamp = int64(binary.LittleEndian.Uint64(data[52:60]))

	// Проверка timestamp (не старше 30 секунд)
	now := time.Now().Unix()
	if abs(now-packet.Timestamp) > 30 {
		return fmt.Errorf("timestamp too old")
	}

	return nil
}

// Обработка discovery пакета
func (s *RelayServer) handleDiscoveryPacket(packet *DiscoveryPacket, clientAddr *net.UDPAddr) {
	// Создаем/обновляем сессию
	session := s.getOrCreateSession(packet.ClientID, clientAddr)

	// Вычисляем shared key через ECDH
	clientPublicKey, err := ecdh.P256().NewPublicKey(packet.PublicKey[:])
	if err != nil {
		s.log(fmt.Sprintf("Invalid client public key: %v", err))
		return
	}

	sharedSecret, err := s.privateKey.ECDH(clientPublicKey)
	if err != nil {
		s.log(fmt.Sprintf("ECDH failed: %v", err))
		return
	}

	// Комбинируем с общим секретом
	hasher := sha256.New()
	hasher.Write(sharedSecret)
	hasher.Write([]byte(SHARED_SECRET))
	session.SharedKey = hasher.Sum(nil)

	// Отправляем ответ
	s.sendHandshakeResponse(session, clientAddr)
}

// Получение или создание сессии
func (s *RelayServer) getOrCreateSession(clientID [16]byte, addr *net.UDPAddr) *ClientSession {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()

	session, exists := s.sessions[clientID]
	if !exists {
		session = &ClientSession{
			ID:         clientID,
			RemoteAddr: addr,
			TCPConns:   make(map[uint32]*TCPConnection),
			UDPConns:   make(map[uint32]*UDPConnection),
			LastSeen:   time.Now(),
		}
		s.sessions[clientID] = session
		s.log(fmt.Sprintf("New session created for client %x", clientID))
		s.totalConnections++
	} else {
		session.RemoteAddr = addr
		session.LastSeen = time.Now()
	}

	return session
}

// Отправка handshake response
func (s *RelayServer) sendHandshakeResponse(session *ClientSession, clientAddr *net.UDPAddr) {
	// Подготавливаем ответ
	response := HandshakeResponse{
		SessionID: session.ID,
		DTLSPort:  8889, // Фиксированный порт для DTLS
	}

	// Копируем публичный ключ сервера
	serverPubBytes := s.publicKey.Bytes()
	copy(response.PublicKey[:], serverPubBytes)

	// Сериализуем ответ
	data := make([]byte, 50) // 16 + 32 + 2
	copy(data[0:16], response.SessionID[:])
	copy(data[16:48], response.PublicKey[:])
	binary.LittleEndian.PutUint16(data[48:50], response.DTLSPort)

	// Отправляем прямо на адрес клиента
	conn, err := net.DialUDP("udp", nil, clientAddr)
	if err != nil {
		s.log(fmt.Sprintf("Failed to dial client: %v", err))
		return
	}
	defer conn.Close()

	_, err = conn.Write(data)
	if err != nil {
		s.log(fmt.Sprintf("Failed to send handshake response: %v", err))
		return
	}

	s.log(fmt.Sprintf("Handshake response sent to %v", clientAddr))
}

// Запуск DTLS сервера
func (s *RelayServer) startDTLSServer() error {
	config := &dtls.Config{
		PSK: func(hint []byte) ([]byte, error) {
			// Простая PSK аутентификация на основе общего секрета
			return []byte(SHARED_SECRET), nil
		},
		PSKIdentityHint: []byte("vpn-relay"),
		CipherSuites:    []dtls.CipherSuiteID{dtls.TLS_PSK_WITH_AES_128_GCM_SHA256},
	}

	addr, err := net.ResolveUDPAddr("udp", ":8889")
	if err != nil {
		return fmt.Errorf("failed to resolve DTLS address: %v", err)
	}

	listener, err := dtls.Listen("udp", addr, config)
	if err != nil {
		return fmt.Errorf("failed to start DTLS listener: %v", err)
	}

	s.dtlsListener = listener
	s.log("DTLS server started on port 8889")

	go s.handleDTLSConnections()
	return nil
}

// Обработка DTLS соединений
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

// Обработка соединения клиента
func (s *RelayServer) handleClientConnection(conn *dtls.Conn) {
	defer conn.Close()

	// Привязываем соединение к сессии
	session := s.findSessionByDTLSConn(conn)
	if session == nil {
		s.log("Could not find session for DTLS connection")
		return
	}

	session.mu.Lock()
	session.DTLSConn = conn
	session.mu.Unlock()

	buffer := make([]byte, MAX_PACKET_SIZE)

	for {
		// Читаем пакет с заголовком
		n, err := conn.Read(buffer)
		if err != nil {
			s.log(fmt.Sprintf("Client read error: %v", err))
			break
		}

		if n < 20 { // Минимальный размер заголовка
			continue
		}

		// Парсим заголовок
		var header PacketHeader
		header.Type = binary.LittleEndian.Uint32(buffer[0:4])
		header.ID = binary.LittleEndian.Uint32(buffer[4:8])
		header.Length = binary.LittleEndian.Uint32(buffer[8:12])
		header.Timestamp = int64(binary.LittleEndian.Uint64(buffer[12:20]))

		if header.Length > MAX_PACKET_SIZE-20 {
			s.log("Packet too large, ignoring")
			continue
		}

		payload := buffer[20 : 20+header.Length]

		// Обновляем статистику
		session.mu.Lock()
		session.PacketsIn++
		session.BytesIn += uint64(n)
		session.LastSeen = time.Now()
		session.mu.Unlock()

		// Обрабатываем пакет
		go s.handlePacket(session, &header, payload)
	}
}

// Поиск сессии по DTLS соединению
func (s *RelayServer) findSessionByDTLSConn(conn *dtls.Conn) *ClientSession {
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()

	remoteAddr := conn.RemoteAddr().String()
	for _, session := range s.sessions {
		if session.RemoteAddr != nil && session.RemoteAddr.String() == remoteAddr {
			return session
		}
	}
	return nil
}

// Обработка пакета
func (s *RelayServer) handlePacket(session *ClientSession, header *PacketHeader, payload []byte) {
	switch header.Type {
	case PACKET_HTTP:
		s.handleHTTPRequest(session, header, payload)
	case PACKET_TCP:
		s.handleTCPRequest(session, header, payload)
	case PACKET_DNS:
		s.handleDNSRequest(session, header, payload)
	case PACKET_UDP:
		s.handleUDPRequest(session, header, payload)
	default:
		s.log(fmt.Sprintf("Unknown packet type: %d", header.Type))
		s.sendErrorResponse(session, header.ID, "Unknown packet type")
	}
}

// Обработка HTTP запроса
func (s *RelayServer) handleHTTPRequest(session *ClientSession, header *PacketHeader, payload []byte) {
	if len(payload) < 6 {
		s.sendErrorResponse(session, header.ID, "Invalid HTTP payload")
		return
	}

	// Парсим: [2 байта длина адреса][адрес][HTTP данные]
	addrLen := binary.LittleEndian.Uint16(payload[0:2])
	if len(payload) < int(2+addrLen) {
		s.sendErrorResponse(session, header.ID, "Invalid address length")
		return
	}

	targetAddr := string(payload[2 : 2+addrLen])
	httpData := payload[2+addrLen:]

	// Устанавливаем TCP соединение
	conn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		s.log(fmt.Sprintf("Failed to connect to %s: %v", targetAddr, err))
		s.sendErrorResponse(session, header.ID, fmt.Sprintf("Connection failed: %v", err))
		return
	}
	defer conn.Close()

	// Отправляем HTTP запрос
	_, err = conn.Write(httpData)
	if err != nil {
		s.sendErrorResponse(session, header.ID, fmt.Sprintf("Write failed: %v", err))
		return
	}

	// Читаем ответ с таймаутом
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	response := make([]byte, MAX_PACKET_SIZE)
	n, err := conn.Read(response)
	if err != nil && err != io.EOF {
		s.sendErrorResponse(session, header.ID, fmt.Sprintf("Read failed: %v", err))
		return
	}

	// Отправляем ответ клиенту
	s.sendResponse(session, header.ID, PACKET_RESPONSE, response[:n])
	s.log(fmt.Sprintf("HTTP request to %s completed (%d bytes)", targetAddr, n))
}

// Обработка TCP запроса (установка постоянного соединения)
func (s *RelayServer) handleTCPRequest(session *ClientSession, header *PacketHeader, payload []byte) {
	if len(payload) < 6 {
		s.sendErrorResponse(session, header.ID, "Invalid TCP payload")
		return
	}

	// Парсим команду: [1 байт команда][4 байта connection ID][данные]
	command := payload[0]
	connID := binary.LittleEndian.Uint32(payload[1:5])
	data := payload[5:]

	switch command {
	case 1: // Новое соединение
		s.handleTCPConnect(session, header, connID, data)
	case 2: // Отправка данных
		s.handleTCPSend(session, header, connID, data)
	case 3: // Закрытие соединения
		s.handleTCPClose(session, header, connID)
	default:
		s.sendErrorResponse(session, header.ID, "Invalid TCP command")
	}
}

// Установка TCP соединения
func (s *RelayServer) handleTCPConnect(session *ClientSession, header *PacketHeader, connID uint32, data []byte) {
	if len(data) < 2 {
		s.sendErrorResponse(session, header.ID, "Invalid connect data")
		return
	}

	addrLen := binary.LittleEndian.Uint16(data[0:2])
	if len(data) < int(2+addrLen) {
		s.sendErrorResponse(session, header.ID, "Invalid address")
		return
	}

	targetAddr := string(data[2 : 2+addrLen])

	// Устанавливаем соединение
	conn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		s.log(fmt.Sprintf("TCP connect to %s failed: %v", targetAddr, err))
		s.sendErrorResponse(session, header.ID, fmt.Sprintf("Connect failed: %v", err))
		return
	}

	// Сохраняем соединение
	tcpConn := &TCPConnection{
		ID:         connID,
		LocalConn:  conn,
		RemoteAddr: targetAddr,
		CreatedAt:  time.Now(),
		LastUsed:   time.Now(),
	}

	session.mu.Lock()
	session.TCPConns[connID] = tcpConn
	session.ConnIDCounter = max(session.ConnIDCounter, connID)
	session.mu.Unlock()

	// Запускаем горутину для чтения данных
	go s.handleTCPRead(session, tcpConn)

	// Отправляем подтверждение
	s.sendResponse(session, header.ID, PACKET_RESPONSE, []byte("connected"))
	s.log(fmt.Sprintf("TCP connection %d established to %s", connID, targetAddr))
}

// Отправка данных через TCP
func (s *RelayServer) handleTCPSend(session *ClientSession, header *PacketHeader, connID uint32, data []byte) {
	session.mu.RLock()
	tcpConn, exists := session.TCPConns[connID]
	session.mu.RUnlock()

	if !exists {
		s.sendErrorResponse(session, header.ID, "Connection not found")
		return
	}

	tcpConn.mu.Lock()
	tcpConn.LastUsed = time.Now()
	_, err := tcpConn.LocalConn.Write(data)
	tcpConn.mu.Unlock()

	if err != nil {
		s.log(fmt.Sprintf("TCP write error on connection %d: %v", connID, err))
		s.sendErrorResponse(session, header.ID, fmt.Sprintf("Write failed: %v", err))

		// Закрываем соединение при ошибке
		session.mu.Lock()
		delete(session.TCPConns, connID)
		session.mu.Unlock()
		tcpConn.LocalConn.Close()
		return
	}

	s.sendResponse(session, header.ID, PACKET_RESPONSE, []byte("sent"))
}

// Чтение данных из TCP соединения
func (s *RelayServer) handleTCPRead(session *ClientSession, tcpConn *TCPConnection) {
	defer func() {
		tcpConn.LocalConn.Close()
		session.mu.Lock()
		delete(session.TCPConns, tcpConn.ID)
		session.mu.Unlock()
	}()

	buffer := make([]byte, 32768)

	for {
		tcpConn.LocalConn.SetReadDeadline(time.Now().Add(TCP_TIMEOUT * time.Second))
		n, err := tcpConn.LocalConn.Read(buffer)
		if err != nil {
			if !strings.Contains(err.Error(), "timeout") {
				s.log(fmt.Sprintf("TCP read error on connection %d: %v", tcpConn.ID, err))
			}
			break
		}

		tcpConn.mu.Lock()
		tcpConn.LastUsed = time.Now()
		tcpConn.mu.Unlock()

		// Отправляем данные клиенту
		responseData := make([]byte, 5+n)
		responseData[0] = 4 // TCP данные
		binary.LittleEndian.PutUint32(responseData[1:5], tcpConn.ID)
		copy(responseData[5:], buffer[:n])

		s.sendResponse(session, 0, PACKET_TCP, responseData)
	}
}

// Закрытие TCP соединения
func (s *RelayServer) handleTCPClose(session *ClientSession, header *PacketHeader, connID uint32) {
	session.mu.Lock()
	tcpConn, exists := session.TCPConns[connID]
	if exists {
		delete(session.TCPConns, connID)
	}
	session.mu.Unlock()

	if exists {
		tcpConn.LocalConn.Close()
		s.sendResponse(session, header.ID, PACKET_RESPONSE, []byte("closed"))
		s.log(fmt.Sprintf("TCP connection %d closed", connID))
	} else {
		s.sendErrorResponse(session, header.ID, "Connection not found")
	}
}

// Обработка DNS запроса
func (s *RelayServer) handleDNSRequest(session *ClientSession, header *PacketHeader, payload []byte) {
	// Парсим DNS запрос
	msg := new(dns.Msg)
	err := msg.Unpack(payload)
	if err != nil {
		s.log(fmt.Sprintf("Invalid DNS query: %v", err))
		s.sendErrorResponse(session, header.ID, "Invalid DNS query")
		return
	}

	if len(msg.Question) == 0 {
		s.sendErrorResponse(session, header.ID, "No questions in DNS query")
		return
	}

	question := msg.Question[0]
	s.log(fmt.Sprintf("DNS query for %s (type %d)", question.Name, question.Qtype))

	// Проверяем кэш
	cacheKey := s.getDNSCacheKey(msg)
	if cachedResponse := s.getDNSFromCache(cacheKey); cachedResponse != nil {
		responseData, err := cachedResponse.Pack()
		if err == nil {
			s.sendResponse(session, header.ID, PACKET_RESPONSE, responseData)
			s.log(fmt.Sprintf("DNS query for %s resolved from cache", question.Name))
			return
		}
	}

	// Выполняем запрос к DNS серверам
	var response *dns.Msg
	for _, server := range s.dnsServers {
		response, _, err = s.dnsClient.Exchange(msg, server)
		if err == nil && response != nil {
			break
		}
		s.log(fmt.Sprintf("DNS query to %s failed: %v", server, err))
	}

	if response == nil {
		s.log(fmt.Sprintf("All DNS servers failed for query %s", question.Name))
		s.sendErrorResponse(session, header.ID, "DNS resolution failed")
		return
	}

	// Кэшируем ответ
	s.cacheDNSResponse(cacheKey, response)

	// Отправляем ответ клиенту
	responseData, err := response.Pack()
	if err != nil {
		s.log(fmt.Sprintf("Failed to pack DNS response: %v", err))
		s.sendErrorResponse(session, header.ID, "Failed to pack DNS response")
		return
	}

	s.sendResponse(session, header.ID, PACKET_RESPONSE, responseData)
	s.log(fmt.Sprintf("DNS query for %s resolved successfully (%d answers)", question.Name, len(response.Answer)))
}

// Генерация ключа кэша DNS
func (s *RelayServer) getDNSCacheKey(msg *dns.Msg) string {
	if len(msg.Question) == 0 {
		return ""
	}
	q := msg.Question[0]
	return fmt.Sprintf("%s:%d:%d", strings.ToLower(q.Name), q.Qtype, q.Qclass)
}

// Получение DNS ответа из кэша
func (s *RelayServer) getDNSFromCache(key string) *dns.Msg {
	if key == "" {
		return nil
	}

	s.dnsCacheMu.RLock()
	defer s.dnsCacheMu.RUnlock()

	entry, exists := s.dnsCache[key]
	if !exists || time.Now().After(entry.ExpiresAt) {
		return nil
	}

	return entry.Response.Copy()
}

// Кэширование DNS ответа
func (s *RelayServer) cacheDNSResponse(key string, response *dns.Msg) {
	if key == "" || response == nil {
		return
	}

	// Определяем TTL для кэширования
	ttl := uint32(300) // 5 минут по умолчанию

	for _, rr := range response.Answer {
		if rr.Header().Ttl > 0 && rr.Header().Ttl < ttl {
			ttl = rr.Header().Ttl
		}
	}

	// Минимальный TTL 60 секунд, максимальный 3600 секунд
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

// Обработка UDP запроса
func (s *RelayServer) handleUDPRequest(session *ClientSession, header *PacketHeader, payload []byte) {
	if len(payload) < 6 {
		s.sendErrorResponse(session, header.ID, "Invalid UDP payload")
		return
	}

	// Парсим команду: [1 байт команда][4 байта connection ID][данные]
	command := payload[0]
	connID := binary.LittleEndian.Uint32(payload[1:5])
	data := payload[5:]

	switch command {
	case 1: // Новое UDP соединение
		s.handleUDPConnect(session, header, connID, data)
	case 2: // Отправка UDP данных
		s.handleUDPSend(session, header, connID, data)
	case 3: // Закрытие UDP соединения
		s.handleUDPClose(session, header, connID)
	default:
		s.sendErrorResponse(session, header.ID, "Invalid UDP command")
	}
}

// Установка UDP соединения
func (s *RelayServer) handleUDPConnect(session *ClientSession, header *PacketHeader, connID uint32, data []byte) {
	if len(data) < 2 {
		s.sendErrorResponse(session, header.ID, "Invalid UDP connect data")
		return
	}

	addrLen := binary.LittleEndian.Uint16(data[0:2])
	if len(data) < int(2+addrLen) {
		s.sendErrorResponse(session, header.ID, "Invalid UDP address")
		return
	}

	targetAddr := string(data[2 : 2+addrLen])

	// Резолвим UDP адрес
	udpAddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		s.log(fmt.Sprintf("Failed to resolve UDP address %s: %v", targetAddr, err))
		s.sendErrorResponse(session, header.ID, fmt.Sprintf("Address resolution failed: %v", err))
		return
	}

	// Создаем UDP соединение
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		s.log(fmt.Sprintf("Failed to create UDP connection to %s: %v", targetAddr, err))
		s.sendErrorResponse(session, header.ID, fmt.Sprintf("UDP connection failed: %v", err))
		return
	}

	// Сохраняем соединение
	udpConn := &UDPConnection{
		ID:         connID,
		LocalConn:  conn,
		RemoteAddr: udpAddr,
		CreatedAt:  time.Now(),
		LastUsed:   time.Now(),
	}

	session.mu.Lock()
	session.UDPConns[connID] = udpConn
	session.ConnIDCounter = max(session.ConnIDCounter, connID)
	session.mu.Unlock()

	// Запускаем горутину для чтения UDP данных
	go s.handleUDPRead(session, udpConn)

	// Отправляем подтверждение
	s.sendResponse(session, header.ID, PACKET_RESPONSE, []byte("connected"))
	s.log(fmt.Sprintf("UDP connection %d established to %s", connID, targetAddr))
}

// Отправка UDP данных
func (s *RelayServer) handleUDPSend(session *ClientSession, header *PacketHeader, connID uint32, data []byte) {
	session.mu.RLock()
	udpConn, exists := session.UDPConns[connID]
	session.mu.RUnlock()

	if !exists {
		s.sendErrorResponse(session, header.ID, "UDP connection not found")
		return
	}

	udpConn.mu.Lock()
	udpConn.LastUsed = time.Now()
	_, err := udpConn.LocalConn.Write(data)
	udpConn.mu.Unlock()

	if err != nil {
		s.log(fmt.Sprintf("UDP write error on connection %d: %v", connID, err))
		s.sendErrorResponse(session, header.ID, fmt.Sprintf("UDP write failed: %v", err))

		// Закрываем соединение при ошибке
		session.mu.Lock()
		delete(session.UDPConns, connID)
		session.mu.Unlock()
		udpConn.LocalConn.Close()
		return
	}

	s.sendResponse(session, header.ID, PACKET_RESPONSE, []byte("sent"))
}

// Чтение UDP данных
func (s *RelayServer) handleUDPRead(session *ClientSession, udpConn *UDPConnection) {
	defer func() {
		udpConn.LocalConn.Close()
		session.mu.Lock()
		delete(session.UDPConns, udpConn.ID)
		session.mu.Unlock()
	}()

	buffer := make([]byte, 65507) // Максимальный размер UDP пакета

	for {
		udpConn.LocalConn.SetReadDeadline(time.Now().Add(TCP_TIMEOUT * time.Second))
		n, err := udpConn.LocalConn.Read(buffer)
		if err != nil {
			if !strings.Contains(err.Error(), "timeout") {
				s.log(fmt.Sprintf("UDP read error on connection %d: %v", udpConn.ID, err))
			}
			break
		}

		udpConn.mu.Lock()
		udpConn.LastUsed = time.Now()
		udpConn.mu.Unlock()

		// Отправляем данные клиенту
		responseData := make([]byte, 5+n)
		responseData[0] = 4 // UDP данные
		binary.LittleEndian.PutUint32(responseData[1:5], udpConn.ID)
		copy(responseData[5:], buffer[:n])

		s.sendResponse(session, 0, PACKET_UDP, responseData)
	}
}

// Закрытие UDP соединения
func (s *RelayServer) handleUDPClose(session *ClientSession, header *PacketHeader, connID uint32) {
	session.mu.Lock()
	udpConn, exists := session.UDPConns[connID]
	if exists {
		delete(session.UDPConns, connID)
	}
	session.mu.Unlock()

	if exists {
		udpConn.LocalConn.Close()
		s.sendResponse(session, header.ID, PACKET_RESPONSE, []byte("closed"))
		s.log(fmt.Sprintf("UDP connection %d closed", connID))
	} else {
		s.sendErrorResponse(session, header.ID, "UDP connection not found")
	}
}

// Отправка ответа клиенту
func (s *RelayServer) sendResponse(session *ClientSession, requestID uint32, packetType uint32, data []byte) {
	if session.DTLSConn == nil {
		return
	}

	// Создаем заголовок ответа
	header := PacketHeader{
		Type:      packetType,
		ID:        requestID,
		Length:    uint32(len(data)),
		Timestamp: time.Now().Unix(),
	}

	// Сериализуем пакет
	packet := make([]byte, 20+len(data))
	binary.LittleEndian.PutUint32(packet[0:4], header.Type)
	binary.LittleEndian.PutUint32(packet[4:8], header.ID)
	binary.LittleEndian.PutUint32(packet[8:12], header.Length)
	binary.LittleEndian.PutUint64(packet[12:20], uint64(header.Timestamp))
	copy(packet[20:], data)

	// Отправляем
	session.mu.Lock()
	_, err := session.DTLSConn.Write(packet)
	if err == nil {
		session.PacketsOut++
		session.BytesOut += uint64(len(packet))
	}
	session.mu.Unlock()

	if err != nil {
		s.log(fmt.Sprintf("Failed to send response: %v", err))
	}

	// Обновляем общую статистику
	s.totalBytes += uint64(len(packet))
}

// Отправка ошибки клиенту
func (s *RelayServer) sendErrorResponse(session *ClientSession, requestID uint32, errorMsg string) {
	s.sendResponse(session, requestID, PACKET_ERROR, []byte(errorMsg))
}

// Вспомогательные функции
func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func max(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

// Логирование
func (s *RelayServer) log(message string) {
	timestamp := time.Now().Format("15:04:05")
	logMessage := fmt.Sprintf("[%s] %s", timestamp, message)

	// Отправляем в канал для GUI
	select {
	case s.logChan <- logMessage:
	default:
		// Канал переполнен, пропускаем
	}

	// Также выводим в консоль
	log.Println(message)
}

// Создание GUI
func (s *RelayServer) createGUI() fyne.Window {
	myApp := app.New()
	myWindow := myApp.NewWindow("VPN Relay Server")
	myWindow.Resize(fyne.NewSize(800, 600))

	// Статус сервера
	s.statusLabel = widget.NewLabel("Server Status: Stopped")
	s.statusLabel.TextStyle.Bold = true

	// Кнопки управления
	startButton := widget.NewButton("Start Server", func() {
		go s.startServer()
	})

	stopButton := widget.NewButton("Stop Server", func() {
		s.stopServer()
	})

	// Список клиентов
	s.clientsList = widget.NewList(
		func() int {
			s.sessionsMu.RLock()
			defer s.sessionsMu.RUnlock()
			return len(s.sessions)
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("Template")
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			s.sessionsMu.RLock()
			defer s.sessionsMu.RUnlock()

			i := 0
			for sessionID, session := range s.sessions {
				if i == id {
					label := obj.(*widget.Label)
					session.mu.RLock()
					text := fmt.Sprintf("Client %x - %s (TCP:%d UDP:%d) In:%.1fKB Out:%.1fKB",
						sessionID[:4],
						session.RemoteAddr.String(),
						len(session.TCPConns),
						len(session.UDPConns),
						float64(session.BytesIn)/1024,
						float64(session.BytesOut)/1024)
					session.mu.RUnlock()
					label.SetText(text)
					break
				}
				i++
			}
		},
	)

	// Статистика
	s.statsLabel = widget.NewLabel("Statistics: No data")

	// Лог
	s.logText = widget.NewMultiLineEntry()
	s.logText.SetText("Server log will appear here...\n")
	s.logText.Wrapping = fyne.TextWrapWord
	logScroll := container.NewScroll(s.logText)
	logScroll.SetMinSize(fyne.NewSize(400, 200))

	// Настройки
	dnsServersEntry := widget.NewEntry()
	dnsServersEntry.SetText(strings.Join(s.dnsServers, ", "))
	dnsServersEntry.OnChanged = func(text string) {
		servers := strings.Split(text, ",")
		for i := range servers {
			servers[i] = strings.TrimSpace(servers[i])
		}
		s.dnsServers = servers
	}

	// Компоновка
	controlsContainer := container.NewHBox(startButton, stopButton)

	statsContainer := container.NewVBox(
		s.statusLabel,
		s.statsLabel,
		widget.NewSeparator(),
	)

	settingsContainer := container.NewVBox(
		widget.NewLabel("DNS Servers:"),
		dnsServersEntry,
		widget.NewSeparator(),
	)

	clientsContainer := container.NewVBox(
		widget.NewLabel("Active Clients:"),
		container.NewBorder(nil, nil, nil, nil, s.clientsList),
	)

	logContainer := container.NewVBox(
		widget.NewLabel("Server Log:"),
		logScroll,
	)

	leftPanel := container.NewVBox(
		statsContainer,
		settingsContainer,
		controlsContainer,
		clientsContainer,
	)

	content := container.NewHSplit(leftPanel, logContainer)
	content.SetOffset(0.4)

	myWindow.SetContent(content)

	// Запускаем горутину обновления GUI
	go s.updateGUI()

	return myWindow
}

// Обновление GUI
func (s *RelayServer) updateGUI() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopChan:
			return
		case logMessage := <-s.logChan:
			if s.logText != nil {
				currentText := s.logText.Text
				newText := currentText + logMessage + "\n"

				// Ограничиваем размер лога
				lines := strings.Split(newText, "\n")
				if len(lines) > 1000 {
					lines = lines[len(lines)-1000:]
					newText = strings.Join(lines, "\n")
				}

				s.logText.SetText(newText)
				s.logText.CursorRow = len(lines) - 1
			}
		case <-ticker.C:
			if s.statusLabel != nil {
				s.updateStats()
				s.clientsList.Refresh()
			}
		}
	}
}

// Обновление статистики
func (s *RelayServer) updateStats() {
	s.sessionsMu.RLock()
	activeClients := len(s.sessions)

	var totalBytesIn, totalBytesOut uint64
	var totalPacketsIn, totalPacketsOut uint64

	for _, session := range s.sessions {
		session.mu.RLock()
		totalBytesIn += session.BytesIn
		totalBytesOut += session.BytesOut
		totalPacketsIn += session.PacketsIn
		totalPacketsOut += session.PacketsOut
		session.mu.RUnlock()
	}
	s.sessionsMu.RUnlock()

	uptime := time.Since(s.startTime)

	if s.multicastConn != nil && s.dtlsListener != nil {
		s.statusLabel.SetText("Server Status: Running")
	} else {
		s.statusLabel.SetText("Server Status: Stopped")
	}

	statsText := fmt.Sprintf(
		"Uptime: %v | Clients: %d | Total Connections: %d\n"+
			"Traffic In: %.2f MB | Traffic Out: %.2f MB\n"+
			"Packets In: %d | Packets Out: %d\n"+
			"DNS Cache entries: %d",
		uptime.Truncate(time.Second),
		activeClients,
		s.totalConnections,
		float64(totalBytesIn)/(1024*1024),
		float64(totalBytesOut)/(1024*1024),
		totalPacketsIn,
		totalPacketsOut,
		len(s.dnsCache),
	)

	s.statsLabel.SetText(statsText)
}

// Запуск сервера
func (s *RelayServer) startServer() {
	s.log("Starting VPN Relay Server...")

	// Запуск multicast listener
	if err := s.startMulticastListener(); err != nil {
		s.log(fmt.Sprintf("Failed to start multicast listener: %v", err))
		return
	}

	// Запуск DTLS сервера
	if err := s.startDTLSServer(); err != nil {
		s.log(fmt.Sprintf("Failed to start DTLS server: %v", err))
		s.multicastConn.Close()
		s.multicastConn = nil
		return
	}

	s.log("VPN Relay Server started successfully")
	s.log(fmt.Sprintf("Multicast discovery: %s", MULTICAST_ADDR))
	s.log(fmt.Sprintf("DTLS server: port 8889"))
	s.log(fmt.Sprintf("DNS servers: %s", strings.Join(s.dnsServers, ", ")))
}

// Остановка сервера
func (s *RelayServer) stopServer() {
	s.log("Stopping VPN Relay Server...")

	// Сигнализируем о остановке
	select {
	case <-s.stopChan:
		// Уже закрыт
	default:
		close(s.stopChan)
	}

	// Закрываем multicast соединение
	if s.multicastConn != nil {
		s.multicastConn.Close()
		s.multicastConn = nil
	}

	// Закрываем DTLS listener
	if s.dtlsListener != nil {
		s.dtlsListener.Close()
		s.dtlsListener = nil
	}

	// Закрываем все сессии
	s.sessionsMu.Lock()
	for _, session := range s.sessions {
		session.cleanup()
	}
	s.sessions = make(map[[16]byte]*ClientSession)
	s.sessionsMu.Unlock()

	// Очищаем DNS кэш
	s.dnsCacheMu.Lock()
	s.dnsCache = make(map[string]*DNSCacheEntry)
	s.dnsCacheMu.Unlock()

	// Создаем новый канал остановки для следующего запуска
	s.stopChan = make(chan struct{})

	s.log("VPN Relay Server stopped")
}

// Дополняем структуру RelayServer недостающими полями
func (s *RelayServer) initializeGUIFields() {
	// Инициализируем GUI поля в NewRelayServer, если они не были инициализированы
	if s.statusLabel == nil {
		s.statusLabel = widget.NewLabel("Server Status: Stopped")
	}
	if s.clientsList == nil {
		s.clientsList = widget.NewList(func() int { return 0 },
			func() fyne.CanvasObject { return widget.NewLabel("") },
			func(int, fyne.CanvasObject) {})
	}
	if s.logText == nil {
		s.logText = widget.NewMultiLineEntry()
	}
	if s.statsLabel == nil {
		s.statsLabel = widget.NewLabel("Statistics: No data")
	}
}

// Основная функция
func main() {
	// Создаем сервер
	server, err := NewRelayServer()
	if err != nil {
		log.Fatalf("Failed to create relay server: %v", err)
	}

	// Инициализируем GUI поля
	server.initializeGUIFields()

	// Создаем GUI
	window := server.createGUI()

	// Обработчик закрытия окна
	window.SetCloseIntercept(func() {
		server.stopServer()
		window.Close()
	})

	// Показываем окно и запускаем приложение
	window.ShowAndRun()
}
