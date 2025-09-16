package server

import (
	"testing"
	"time"
)

func TestNewRelayServer(t *testing.T) {
	srv, err := NewRelayServer()
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer srv.Stop()

	if len(srv.GetDNSServers()) == 0 {
		t.Fatalf("expected dns servers to be populated")
	}

	stats := srv.Stats()
	if stats.ActiveClients != 0 {
		t.Fatalf("expected no active clients")
	}
	if stats.Running {
		t.Fatalf("server should not be running before Start")
	}

	summaries := srv.SessionSummaries()
	if len(summaries) != 0 {
		t.Fatalf("expected no session summaries")
	}

	srv.SetDNSServers([]string{"8.8.8.8:53"})
	servers := srv.GetDNSServers()
	if len(servers) != 1 || servers[0] != "8.8.8.8:53" {
		t.Fatalf("unexpected dns servers: %v", servers)
	}

	srv.SetDNSServers(nil)
	if len(srv.GetDNSServers()) == 0 {
		t.Fatalf("expected fallback dns servers")
	}

	removed := srv.ClearDNSCache()
	if removed != 0 {
		t.Fatalf("expected empty cache, got %d", removed)
	}

	if srv.Stats().Uptime < 0 {
		t.Fatalf("expected non-negative uptime")
	}
}

func TestStatsUpdatesAfterStartStop(t *testing.T) {
	srv, err := NewRelayServer()
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer srv.Stop()

	if err := srv.Start(); err != nil {
		t.Skipf("skipping start/stop test due to environment: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
	stats := srv.Stats()
	if !stats.Running {
		t.Fatalf("expected running status after start")
	}

	srv.Stop()
	time.Sleep(50 * time.Millisecond)
	stats = srv.Stats()
	if stats.Running {
		t.Fatalf("expected stopped status")
	}
}
