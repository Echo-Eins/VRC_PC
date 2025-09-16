package client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"vpn-relay/protocol"

	"github.com/miekg/dns"
)

// DoHTTP proxies a raw HTTP request through the relay and returns the raw
// response body provided by the server.
func (c *Client) DoHTTP(ctx context.Context, targetAddr string, request []byte) ([]byte, error) {
	if targetAddr == "" {
		return nil, errors.New("target address is required")
	}
	if len(targetAddr) > 0xFFFF {
		return nil, fmt.Errorf("target address too long: %d", len(targetAddr))
	}

	payload := make([]byte, 2+len(targetAddr)+len(request))
	binary.LittleEndian.PutUint16(payload[0:2], uint16(len(targetAddr)))
	copy(payload[2:2+len(targetAddr)], []byte(targetAddr))
	copy(payload[2+len(targetAddr):], request)

	response, _, err := c.sendRequest(ctx, protocol.PacketHTTP, payload, []uint32{protocol.PacketResponse})
	if err != nil {
		return nil, err
	}
	return response, nil
}

// QueryDNS forwards the DNS request through the relay and returns the parsed
// DNS response.
func (c *Client) QueryDNS(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if msg == nil {
		return nil, errors.New("dns message is required")
	}

	wire, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack dns message: %w", err)
	}

	response, _, err := c.sendRequest(ctx, protocol.PacketDNS, wire, []uint32{protocol.PacketDNS})
	if err != nil {
		return nil, err
	}

	out := new(dns.Msg)
	if err := out.Unpack(response); err != nil {
		return nil, fmt.Errorf("unpack dns response: %w", err)
	}
	return out, nil
}
