package main

import (
	"log"

	"fyne.io/fyne/v2/app"

	"vpn-relay/gui"
	"vpn-relay/server"
)

func main() {
	srv, err := server.NewRelayServer()
	if err != nil {
		log.Fatalf("Failed to create relay server: %v", err)
	}

	application := app.New()
	manager := gui.NewWithApp(application, srv)
	manager.Run()
}
