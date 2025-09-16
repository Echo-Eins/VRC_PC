package protocol

import (
	"encoding/binary"
	"fmt"
	"time"
)

const (
	MagicBytes = "VPNR"

	PacketHTTP     = 1
	PacketTCP      = 2
	PacketDNS      = 3
	PacketUDP      = 4
	PacketResponse = 100
	PacketError    = 200
)

const discoveryTimeTolerance = 30 * time.Second

type DiscoveryPacket struct {
	Magic     [4]byte
	ClientID  [16]byte
	PublicKey [65]byte
	Timestamp int64
}

type HandshakeResponse struct {
	SessionID [16]byte
	PublicKey [65]byte
	DTLSPort  uint16
}

type PacketHeader struct {
	Type      uint32
	ID        uint32
	Length    uint32
	Timestamp int64
}

func ParseDiscoveryPacket(data []byte, now time.Time) (*DiscoveryPacket, error) {
	if len(data) < 93 {
		return nil, fmt.Errorf("packet too short: %d bytes, need 93", len(data))
	}

	var packet DiscoveryPacket
	copy(packet.Magic[:], data[0:4])
	if string(packet.Magic[:]) != MagicBytes {
		return nil, fmt.Errorf("invalid magic bytes: got %q, expected %q", string(packet.Magic[:]), MagicBytes)
	}

	copy(packet.ClientID[:], data[4:20])
	copy(packet.PublicKey[:], data[20:85])
	packet.Timestamp = int64(binary.LittleEndian.Uint64(data[85:93]))

	timestamp := time.Unix(packet.Timestamp, 0)
	if diff := now.Sub(timestamp); diff > discoveryTimeTolerance || diff < -discoveryTimeTolerance {
		return nil, fmt.Errorf("timestamp out of range: %v", diff)
	}

	return &packet, nil
}

func SerializeHandshakeResponse(response HandshakeResponse) []byte {
	data := make([]byte, 83)
	copy(data[0:16], response.SessionID[:])
	copy(data[16:81], response.PublicKey[:])
	binary.LittleEndian.PutUint16(data[81:83], response.DTLSPort)
	return data
}
