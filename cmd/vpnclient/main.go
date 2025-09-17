package main

import (
	"fyne.io/fyne/v2/app"
	"vpn-relay/gui"
)

func main() {
	application := app.New()
	manager := gui.NewClientWithApp(application)
	manager.Run()
}
