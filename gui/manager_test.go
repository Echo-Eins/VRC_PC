package gui

import (
	"testing"

	"vpn-relay/server"

	"fyne.io/fyne/v2/test"
)

func TestManagerInitialization(t *testing.T) {
	srv, err := server.NewRelayServer()
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer srv.Stop()

	app := test.NewApp()
	manager := NewWithApp(app, srv)
	if manager == nil {
		t.Fatalf("expected manager")
	}
	if manager.Window() == nil {
		t.Fatalf("expected window to be created")
	}
	if manager.statusLabel.Text != "Server Status: Stopped" {
		t.Fatalf("unexpected initial status: %s", manager.statusLabel.Text)
	}

	manager.Stop()
	manager.Window().Close()
	app.Quit()
}
