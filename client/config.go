package client

import (
	"log"
	"os"
	"time"

	"vpn-relay/config"
)

// Config describes runtime configuration of the VPN relay client.
type Config struct {
	// MulticastAddr is the discovery multicast endpoint.
	MulticastAddr string
	// SharedSecret is a pre-shared key used for DTLS authentication.
	SharedSecret string
	// EnableDebug toggles verbose logging of protocol exchanges.
	EnableDebug bool
	// DiscoveryTimeout limits how long the client waits for a handshake response.
	DiscoveryTimeout time.Duration
	// DTLSConnectTimeout limits the DTLS dialing process.
	DTLSConnectTimeout time.Duration
	// ResponseTimeout is used as a fallback when individual API calls do not
	// provide their own deadline.
	ResponseTimeout time.Duration
	// MaxPacketSize controls the size of buffers used to read from the DTLS
	// connection.
	MaxPacketSize int
	// Logger receives diagnostic messages. If nil a default logger is created.
	Logger *log.Logger
}

// DefaultConfig returns a hardened configuration matching the expectations of
// the relay server.
func DefaultConfig() Config {
	return Config{
		MulticastAddr:      config.MulticastAddr,
		SharedSecret:       config.SharedSecret,
		EnableDebug:        false,
		DiscoveryTimeout:   5 * time.Second,
		DTLSConnectTimeout: 10 * time.Second,
		ResponseTimeout:    15 * time.Second,
		MaxPacketSize:      config.MaxPacketSize,
	}
}

func (c *Config) setDefaults() {
	defaults := DefaultConfig()

	if c.MulticastAddr == "" {
		c.MulticastAddr = defaults.MulticastAddr
	}
	if c.SharedSecret == "" {
		c.SharedSecret = defaults.SharedSecret
	}
	if c.DiscoveryTimeout == 0 {
		c.DiscoveryTimeout = defaults.DiscoveryTimeout
	}
	if c.DTLSConnectTimeout == 0 {
		c.DTLSConnectTimeout = defaults.DTLSConnectTimeout
	}
	if c.ResponseTimeout == 0 {
		c.ResponseTimeout = defaults.ResponseTimeout
	}
	if c.MaxPacketSize <= 0 {
		c.MaxPacketSize = defaults.MaxPacketSize
	}
	if c.Logger == nil {
		c.Logger = log.New(os.Stderr, "vpn-client ", log.LstdFlags|log.Lmicroseconds)
	}
}
