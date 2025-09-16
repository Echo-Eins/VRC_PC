package protocol

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestParseDiscoveryPacket(t *testing.T) {
	now := time.Now()
	data := make([]byte, 93)
	copy(data[0:4], []byte(MagicBytes))
	copy(data[4:20], []byte("1234567890abcdef"))
	data[20] = 0x04
	for i := 21; i < 85; i++ {
		data[i] = byte(i)
	}
	binary.LittleEndian.PutUint64(data[85:93], uint64(now.Unix()))

	packet, err := ParseDiscoveryPacket(data, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if packet.Timestamp != now.Unix() {
		t.Fatalf("expected timestamp %d, got %d", now.Unix(), packet.Timestamp)
	}
}

func TestParseDiscoveryPacketInvalidMagic(t *testing.T) {
	now := time.Now()
	data := make([]byte, 93)
	copy(data[0:4], []byte("FAIL"))
	if _, err := ParseDiscoveryPacket(data, now); err == nil {
		t.Fatalf("expected error for invalid magic")
	}
}

func TestSerializeHandshakeResponse(t *testing.T) {
	var resp HandshakeResponse
	copy(resp.SessionID[:], []byte("session-identifier"))
	resp.PublicKey[0] = 0x04
	resp.DTLSPort = 8889

	data := SerializeHandshakeResponse(resp)
	if len(data) != 83 {
		t.Fatalf("unexpected length: %d", len(data))
	}
	if binary.LittleEndian.Uint16(data[81:83]) != resp.DTLSPort {
		t.Fatalf("unexpected port")
	}
}
