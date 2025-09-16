package client

import "net"

// ClientID returns the identifier generated during discovery.
func (c *Client) ClientID() [16]byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.clientID
}

// SessionID returns the session identifier provided by the server.
func (c *Client) SessionID() [16]byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sessionID
}

// SharedKey returns a copy of the derived shared key produced during the ECDH
// handshake.
func (c *Client) SharedKey() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.sharedKey == nil {
		return nil
	}
	return append([]byte(nil), c.sharedKey...)
}

// RemoteAddr returns the DTLS endpoint discovered for the server.
func (c *Client) RemoteAddr() *net.UDPAddr {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.serverAddr == nil {
		return nil
	}
	addrCopy := *c.serverAddr
	return &addrCopy
}
