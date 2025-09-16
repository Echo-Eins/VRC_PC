package gui

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"vpn-relay/server"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

type Manager struct {
	server *server.RelayServer
	app    fyne.App
	window fyne.Window

	statusLabel *widget.Label
	statsLabel  *widget.Label
	logText     *widget.Entry
	clientsList *widget.List
	dnsEntry    *widget.Entry

	sessionSummaries []server.SessionSummary

	stop      chan struct{}
	stopOnce  sync.Once
	startOnce sync.Once
}

func NewWithApp(application fyne.App, srv *server.RelayServer) *Manager {
	m := &Manager{
		server: srv,
		app:    application,
		stop:   make(chan struct{}),
	}

	m.buildUI()

	return m
}

func (m *Manager) buildUI() {
	m.window = m.app.NewWindow("VPN Relay Server")
	m.window.Resize(fyne.NewSize(800, 600))

	m.statusLabel = widget.NewLabel("Server Status: Stopped")
	m.statusLabel.TextStyle.Bold = true

	startButton := widget.NewButton("Start Server", nil)
	startButton.OnTapped = func() {
		startButton.Disable()
		go func() {
			if err := m.server.Start(); err != nil {
				m.server.Logf("Failed to start server: %v", err)
			}
			m.runOnMain(func() {
				startButton.Enable()
			})
		}()
	}

	stopButton := widget.NewButton("Stop Server", func() {
		go m.server.Stop()
	})

	m.clientsList = widget.NewList(
		func() int {
			return len(m.sessionSummaries)
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("Template")
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			if id < 0 || id >= len(m.sessionSummaries) {
				return
			}
			summary := m.sessionSummaries[id]
			text := fmt.Sprintf("Client %s - %s (TCP:%d UDP:%d) In:%.1fKB Out:%.1fKB",
				summary.ID,
				summary.RemoteAddr,
				summary.TCPCount,
				summary.UDPCount,
				float64(summary.BytesIn)/1024,
				float64(summary.BytesOut)/1024)
			obj.(*widget.Label).SetText(text)
		},
	)

	m.statsLabel = widget.NewLabel("Statistics: No data")

	m.logText = widget.NewMultiLineEntry()
	m.logText.SetText("Server log will appear here...\n")
	m.logText.Wrapping = fyne.TextWrapWord
	logScroll := container.NewScroll(m.logText)
	logScroll.SetMinSize(fyne.NewSize(400, 200))

	m.dnsEntry = widget.NewEntry()
	m.dnsEntry.SetText(strings.Join(m.server.GetDNSServers(), ", "))
	m.dnsEntry.OnChanged = func(text string) {
		servers := strings.Split(text, ",")
		m.server.SetDNSServers(servers)
	}

	showStatsButton := widget.NewButton("Show Detailed Stats", func() {
		go func() {
			stats := m.server.Stats()
			totalBytesIn := stats.TotalBytesIn
			totalBytesOut := stats.TotalBytesOut

			statsMessage := fmt.Sprintf(
				"=== Detailed Server Statistics ===\n"+
					"Active Clients: %d\n"+
					"Total TCP Connections: %d\n"+
					"Total UDP Connections: %d\n"+
					"Total Traffic In: %.2f MB\n"+
					"Total Traffic Out: %.2f MB\n"+
					"DNS Cache Entries: %d\n"+
					"Uptime: %v\n"+
					"Total Connections Since Start: %d",
				stats.ActiveClients,
				stats.TotalTCPConnections,
				stats.TotalUDPConnections,
				float64(totalBytesIn)/(1024*1024),
				float64(totalBytesOut)/(1024*1024),
				stats.DNSCacheEntries,
				stats.Uptime.Truncate(time.Second),
				stats.TotalConnections,
			)

			m.server.Logf("%s", statsMessage)
		}()
	})

	clearCacheButton := widget.NewButton("Clear DNS Cache", func() {
		go func() {
			removed := m.server.ClearDNSCache()
			m.server.Logf("DNS cache cleared (%d entries removed)", removed)
		}()
	})

	controlsContainer := container.NewHBox(
		startButton,
		stopButton,
		widget.NewSeparator(),
		showStatsButton,
		clearCacheButton,
	)

	statsContainer := container.NewVBox(
		m.statusLabel,
		m.statsLabel,
		widget.NewSeparator(),
	)

	settingsContainer := container.NewVBox(
		widget.NewLabel("Configuration:"),
		widget.NewForm(
			widget.NewFormItem("DNS Servers", m.dnsEntry),
		),
		widget.NewLabel("Separate multiple DNS servers with commas"),
		widget.NewSeparator(),
	)

	clientsContainer := container.NewVBox(
		widget.NewLabel("Active Clients:"),
		container.NewBorder(nil, nil, nil, nil, m.clientsList),
	)

	logContainer := container.NewVBox(
		widget.NewLabel("Server Log:"),
		logScroll,
	)

	infoContainer := container.NewVBox(
		widget.NewLabel("VPN Relay Server Information:"),
		widget.NewLabel("• Listens on multicast 224.0.0.251:8888 for discovery"),
		widget.NewLabel("• DTLS server runs on port 8889"),
		widget.NewLabel("• Supports HTTP, TCP, UDP tunneling and DNS resolution"),
		widget.NewLabel("• Uses ECDH + PSK for secure client authentication"),
		widget.NewSeparator(),
	)

	leftPanel := container.NewVBox(
		infoContainer,
		statsContainer,
		settingsContainer,
		controlsContainer,
		clientsContainer,
	)

	content := container.NewHSplit(leftPanel, logContainer)
	content.SetOffset(0.4)

	m.window.SetContent(content)

	m.window.SetCloseIntercept(func() {
		m.Stop()
		m.server.Stop()
		m.window.Close()
	})
}

func (m *Manager) startBackgroundTasks() {
	m.startOnce.Do(func() {
		go m.processLogs()
		go m.updateLoop()
	})
}

func (m *Manager) processLogs() {
	logs := m.server.Logs()
	for {
		select {
		case <-m.stop:
			return
		case msg := <-logs:
			m.runOnMain(func() {
				m.appendLog(msg)
			})
		}
	}
}

func (m *Manager) updateLoop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
			stats := m.server.Stats()
			summaries := m.server.SessionSummaries()

			m.runOnMain(func() {
				m.updateStats(stats)
				m.sessionSummaries = summaries
				m.clientsList.Refresh()
			})
		}
	}
}

func (m *Manager) updateStats(stats server.Stats) {
	if stats.Running {
		m.statusLabel.SetText("Server Status: Running")
	} else {
		m.statusLabel.SetText("Server Status: Stopped")
	}

	statsText := fmt.Sprintf(
		"Uptime: %v | Clients: %d | Total Connections: %d\n"+
			"Traffic In: %.2f MB | Traffic Out: %.2f MB\n"+
			"Packets In: %d | Packets Out: %d\n"+
			"DNS Cache entries: %d",
		stats.Uptime.Truncate(time.Second),
		stats.ActiveClients,
		stats.TotalConnections,
		float64(stats.TotalBytesIn)/(1024*1024),
		float64(stats.TotalBytesOut)/(1024*1024),
		stats.TotalPacketsIn,
		stats.TotalPacketsOut,
		stats.DNSCacheEntries,
	)

	m.statsLabel.SetText(statsText)
}

func (m *Manager) appendLog(message string) {
	currentText := m.logText.Text
	newText := currentText + message + "\n"

	lines := strings.Split(newText, "\n")
	if len(lines) > 1000 {
		lines = lines[len(lines)-1000:]
		newText = strings.Join(lines, "\n")
	}

	m.logText.SetText(newText)
	m.logText.CursorRow = len(lines) - 1
}

func (m *Manager) runOnMain(fn func()) {
	if fn == nil {
		return
	}
	driver := m.app.Driver()
	if driver == nil {
		fn()
		return
	}
	driver.DoFromGoroutine(fn, true)
}

func (m *Manager) Window() fyne.Window {
	return m.window
}

func (m *Manager) Run() {
	m.startBackgroundTasks()
	m.window.ShowAndRun()
}

func (m *Manager) Stop() {
	m.stopOnce.Do(func() {
		close(m.stop)
	})
}
