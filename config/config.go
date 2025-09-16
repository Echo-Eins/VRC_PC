package config

import (
	"net"
	"time"

	"github.com/miekg/dns"
)

const (
	MulticastAddr = "224.0.0.251:8888"
	SharedSecret  = "2108"

	MaxPacketSize = 65536

	SessionTimeout = 5 * time.Minute
	DNSTimeout     = 5 * time.Second
	TCPTimeout     = 30 * time.Second

	DTLSPort       = 8889
	DTLSListenAddr = ":8889"
)

var fallbackDNSServers = []string{"8.8.8.8:53", "1.1.1.1:53"}

func GetSystemDNSServers() []string {
	var servers []string

	if config, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil {
		for _, server := range config.Servers {
			servers = append(servers, net.JoinHostPort(server, "53"))
		}
	}

	if len(servers) == 0 {
		servers = append(servers, fallbackDNSServers...)
	}

	return servers
}

func FallbackDNSServers() []string {
	return append([]string(nil), fallbackDNSServers...)
}
