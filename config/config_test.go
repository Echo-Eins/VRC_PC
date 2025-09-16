package config

import "testing"

func TestGetSystemDNSServers(t *testing.T) {
	servers := GetSystemDNSServers()
	if len(servers) == 0 {
		t.Fatalf("expected at least one DNS server")
	}
}

func TestFallbackDNSServers(t *testing.T) {
	fallback := FallbackDNSServers()
	if len(fallback) == 0 {
		t.Fatalf("expected fallback servers")
	}
	if fallback[0] == "" {
		t.Fatalf("fallback server should not be empty")
	}
}
