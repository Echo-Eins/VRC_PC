package gui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"vpn-relay/client"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/miekg/dns"
)

type ClientManager struct {
	app    fyne.App
	window fyne.Window

	config client.Config

	clientMu sync.Mutex
	client   *client.Client

	operationMu sync.Mutex
	stateMu     sync.RWMutex

	connected     bool
	lastHandshake *client.Handshake

	logMu     sync.Mutex
	logBuffer []string

	clientLogger *log.Logger

	statusLabel     *widget.Label
	handshakeOutput *widget.Entry
	logOutput       *widget.Entry

	multicastEntry *widget.Entry
	secretEntry    *widget.Entry
	discoveryEntry *widget.Entry
	dtlsEntry      *widget.Entry
	responseEntry  *widget.Entry
	maxPacketEntry *widget.Entry
	debugCheck     *widget.Check

	httpAddrEntry     *widget.Entry
	httpRequestEntry  *widget.Entry
	httpTimeoutEntry  *widget.Entry
	httpResponseEntry *widget.Entry

	dnsNameEntry    *widget.Entry
	dnsTypeEntry    *widget.Entry
	dnsTimeoutEntry *widget.Entry
	dnsOutputEntry  *widget.Entry

	tcpAddrEntry        *widget.Entry
	tcpSendEntry        *widget.Entry
	tcpReadTimeoutEntry *widget.Entry
	tcpOutputEntry      *widget.Entry

	udpAddrEntry        *widget.Entry
	udpSendEntry        *widget.Entry
	udpReadTimeoutEntry *widget.Entry
	udpOutputEntry      *widget.Entry
}

func NewClientWithApp(application fyne.App) *ClientManager {
	cfg := client.DefaultConfig()

	manager := &ClientManager{
		app:       application,
		config:    cfg,
		logBuffer: make([]string, 0, 128),
	}

	manager.clientLogger = log.New(&uiLogWriter{manager: manager}, "", log.LstdFlags|log.Lmicroseconds)
	manager.config.Logger = manager.clientLogger

	manager.buildUI()
	manager.setConnected(false)
	manager.setHandshake(nil)

	return manager
}

func (m *ClientManager) buildUI() {
	m.window = m.app.NewWindow("VPN Relay Client")
	m.window.Resize(fyne.NewSize(960, 720))

	m.statusLabel = widget.NewLabel("")

	m.handshakeOutput = widget.NewMultiLineEntry()
	m.handshakeOutput.Disable()
	m.handshakeOutput.Wrapping = fyne.TextWrapWord

	m.logOutput = widget.NewMultiLineEntry()
	m.logOutput.Disable()
	m.logOutput.Wrapping = fyne.TextWrapWord
	logScroll := container.NewScroll(m.logOutput)
	logScroll.SetMinSize(fyne.NewSize(400, 200))

	m.multicastEntry = widget.NewEntry()
	m.multicastEntry.SetText(m.config.MulticastAddr)

	m.secretEntry = widget.NewEntry()
	m.secretEntry.SetText(m.config.SharedSecret)

	m.discoveryEntry = widget.NewEntry()
	m.discoveryEntry.SetText(m.config.DiscoveryTimeout.String())

	m.dtlsEntry = widget.NewEntry()
	m.dtlsEntry.SetText(m.config.DTLSConnectTimeout.String())

	m.responseEntry = widget.NewEntry()
	m.responseEntry.SetText(m.config.ResponseTimeout.String())

	m.maxPacketEntry = widget.NewEntry()
	m.maxPacketEntry.SetText(strconv.Itoa(m.config.MaxPacketSize))

	m.debugCheck = widget.NewCheck("Enable debug logging", nil)
	m.debugCheck.SetChecked(m.config.EnableDebug)

	applyButton := widget.NewButton("Apply Configuration", func() {
		if err := m.applyConfigFromUI(); err != nil {
			m.logf("failed to apply configuration: %v", err)
			m.showError(err)
			return
		}
		go func() {
			if err := m.resetClient(); err != nil {
				m.logf("failed to reset client: %v", err)
				m.showError(err)
				return
			}
			m.logf("configuration applied and client reset")
		}()
	})

	discoverButton := widget.NewButton("Discover", func() {
		m.runOperation("Discovery", func() error {
			cl, err := m.ensureClient()
			if err != nil {
				return err
			}
			_, err = m.performDiscovery(cl)
			return err
		})
	})

	connectButton := widget.NewButton("Connect", func() {
		m.runOperation("Connect", func() error {
			_, err := m.ensureConnected()
			return err
		})
	})

	disconnectButton := widget.NewButton("Disconnect", func() {
		go func() {
			m.logf("disconnecting client")
			if err := m.resetClient(); err != nil {
				m.logf("error during disconnect: %v", err)
				m.showError(err)
				return
			}
			m.logf("client disconnected")
		}()
	})

	configForm := widget.NewForm(
		widget.NewFormItem("Multicast Address", m.multicastEntry),
		widget.NewFormItem("Shared Secret", m.secretEntry),
		widget.NewFormItem("Discovery Timeout", m.discoveryEntry),
		widget.NewFormItem("DTLS Timeout", m.dtlsEntry),
		widget.NewFormItem("Response Timeout", m.responseEntry),
		widget.NewFormItem("Max Packet Size", m.maxPacketEntry),
	)

	sessionControls := container.NewVBox(
		m.statusLabel,
		m.debugCheck,
		widget.NewSeparator(),
		configForm,
		applyButton,
		widget.NewSeparator(),
		widget.NewLabel("Handshake Details:"),
		container.NewScroll(m.handshakeOutput),
		widget.NewSeparator(),
		container.NewHBox(discoverButton, connectButton, disconnectButton),
		widget.NewSeparator(),
		widget.NewLabel("Log Output:"),
		logScroll,
	)

	m.httpAddrEntry = widget.NewEntry()
	m.httpRequestEntry = widget.NewMultiLineEntry()
	m.httpRequestEntry.SetPlaceHolder("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	m.httpTimeoutEntry = widget.NewEntry()
	m.httpTimeoutEntry.SetText(m.config.ResponseTimeout.String())
	m.httpResponseEntry = widget.NewMultiLineEntry()
	m.httpResponseEntry.Disable()
	m.httpResponseEntry.Wrapping = fyne.TextWrapWord
	httpResponseScroll := container.NewScroll(m.httpResponseEntry)
	httpResponseScroll.SetMinSize(fyne.NewSize(400, 200))

	httpSendButton := widget.NewButton("Send HTTP Request", m.executeHTTP)

	httpTab := container.NewVBox(
		widget.NewForm(
			widget.NewFormItem("Target Address", m.httpAddrEntry),
			widget.NewFormItem("Timeout", m.httpTimeoutEntry),
		),
		widget.NewLabel("Raw HTTP Request:"),
		container.NewScroll(m.httpRequestEntry),
		httpSendButton,
		widget.NewSeparator(),
		widget.NewLabel("Response:"),
		httpResponseScroll,
	)

	m.dnsNameEntry = widget.NewEntry()
	m.dnsTypeEntry = widget.NewEntry()
	m.dnsTypeEntry.SetText("A")
	m.dnsTimeoutEntry = widget.NewEntry()
	m.dnsTimeoutEntry.SetText("5s")
	m.dnsOutputEntry = widget.NewMultiLineEntry()
	m.dnsOutputEntry.Disable()
	m.dnsOutputEntry.Wrapping = fyne.TextWrapWord
	dnsOutputScroll := container.NewScroll(m.dnsOutputEntry)
	dnsOutputScroll.SetMinSize(fyne.NewSize(400, 200))

	dnsQueryButton := widget.NewButton("Resolve", m.executeDNS)

	dnsTab := container.NewVBox(
		widget.NewForm(
			widget.NewFormItem("Domain Name", m.dnsNameEntry),
			widget.NewFormItem("Record Type", m.dnsTypeEntry),
			widget.NewFormItem("Timeout", m.dnsTimeoutEntry),
		),
		dnsQueryButton,
		widget.NewSeparator(),
		widget.NewLabel("Response:"),
		dnsOutputScroll,
	)

	m.tcpAddrEntry = widget.NewEntry()
	m.tcpSendEntry = widget.NewMultiLineEntry()
	m.tcpReadTimeoutEntry = widget.NewEntry()
	m.tcpReadTimeoutEntry.SetText("5s")
	m.tcpOutputEntry = widget.NewMultiLineEntry()
	m.tcpOutputEntry.Disable()
	m.tcpOutputEntry.Wrapping = fyne.TextWrapWord
	tcpOutputScroll := container.NewScroll(m.tcpOutputEntry)
	tcpOutputScroll.SetMinSize(fyne.NewSize(400, 200))

	tcpExecuteButton := widget.NewButton("Open TCP Session", m.executeTCP)

	tcpTab := container.NewVBox(
		widget.NewForm(
			widget.NewFormItem("Remote Address", m.tcpAddrEntry),
			widget.NewFormItem("Read Timeout", m.tcpReadTimeoutEntry),
		),
		widget.NewLabel("Payload to Send (optional):"),
		container.NewScroll(m.tcpSendEntry),
		tcpExecuteButton,
		widget.NewSeparator(),
		widget.NewLabel("Received Data:"),
		tcpOutputScroll,
	)

	m.udpAddrEntry = widget.NewEntry()
	m.udpSendEntry = widget.NewMultiLineEntry()
	m.udpReadTimeoutEntry = widget.NewEntry()
	m.udpReadTimeoutEntry.SetText("5s")
	m.udpOutputEntry = widget.NewMultiLineEntry()
	m.udpOutputEntry.Disable()
	m.udpOutputEntry.Wrapping = fyne.TextWrapWord
	udpOutputScroll := container.NewScroll(m.udpOutputEntry)
	udpOutputScroll.SetMinSize(fyne.NewSize(400, 200))

	udpExecuteButton := widget.NewButton("Open UDP Session", m.executeUDP)

	udpTab := container.NewVBox(
		widget.NewForm(
			widget.NewFormItem("Remote Address", m.udpAddrEntry),
			widget.NewFormItem("Read Timeout", m.udpReadTimeoutEntry),
		),
		widget.NewLabel("Datagram Payload (optional):"),
		container.NewScroll(m.udpSendEntry),
		udpExecuteButton,
		widget.NewSeparator(),
		widget.NewLabel("Received Datagrams:"),
		udpOutputScroll,
	)

	tabs := container.NewAppTabs(
		container.NewTabItem("Session", sessionControls),
		container.NewTabItem("HTTP", httpTab),
		container.NewTabItem("DNS", dnsTab),
		container.NewTabItem("TCP", tcpTab),
		container.NewTabItem("UDP", udpTab),
	)

	m.window.SetContent(tabs)
	m.window.SetCloseIntercept(func() {
		go func() {
			if err := m.resetClient(); err != nil {
				m.logf("error while closing client: %v", err)
			}
			m.runOnMain(func() {
				m.window.Close()
			})
		}()
	})
}

func (m *ClientManager) Run() {
	m.window.ShowAndRun()
}

func (m *ClientManager) ensureClient() (*client.Client, error) {
	m.clientMu.Lock()
	defer m.clientMu.Unlock()

	if m.client != nil {
		return m.client, nil
	}

	cfg := m.config
	cfg.Logger = m.clientLogger

	cl, err := client.New(cfg)
	if err != nil {
		return nil, err
	}
	m.client = cl
	return cl, nil
}

func (m *ClientManager) ensureConnected() (*client.Client, error) {
	cl, err := m.ensureClient()
	if err != nil {
		return nil, err
	}
	if m.isConnected() {
		return cl, nil
	}

	handshake, err := m.performDiscovery(cl)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), m.config.DTLSConnectTimeout)
	defer cancel()

	if err := cl.Connect(ctx); err != nil {
		return nil, err
	}

	m.setConnected(true)
	remote := "(unknown)"
	if handshake != nil && handshake.RemoteAddr != nil {
		remote = handshake.RemoteAddr.String()
	}
	m.logf("dtls connection established with %s", remote)
	return cl, nil
}

func (m *ClientManager) performDiscovery(cl *client.Client) (*client.Handshake, error) {
	ctx, cancel := context.WithTimeout(context.Background(), m.config.DiscoveryTimeout)
	defer cancel()

	handshake, err := cl.Discover(ctx)
	if err != nil {
		return nil, err
	}
	m.setHandshake(handshake)
	remote := "(unknown)"
	if handshake.RemoteAddr != nil {
		remote = handshake.RemoteAddr.String()
	}
	m.logf("discovered relay session %x via %s", handshake.SessionID, remote)
	return handshake, nil
}

func (m *ClientManager) applyConfigFromUI() error {
	multicast := strings.TrimSpace(m.multicastEntry.Text)
	if multicast == "" {
		return errors.New("multicast address cannot be empty")
	}
	secret := strings.TrimSpace(m.secretEntry.Text)
	if secret == "" {
		return errors.New("shared secret cannot be empty")
	}

	discoveryTimeout, err := parseDurationWithDefault(m.discoveryEntry.Text, m.config.DiscoveryTimeout)
	if err != nil {
		return fmt.Errorf("invalid discovery timeout: %w", err)
	}
	dtlsTimeout, err := parseDurationWithDefault(m.dtlsEntry.Text, m.config.DTLSConnectTimeout)
	if err != nil {
		return fmt.Errorf("invalid dtls timeout: %w", err)
	}
	responseTimeout, err := parseDurationWithDefault(m.responseEntry.Text, m.config.ResponseTimeout)
	if err != nil {
		return fmt.Errorf("invalid response timeout: %w", err)
	}

	packetSizeText := strings.TrimSpace(m.maxPacketEntry.Text)
	if packetSizeText == "" {
		return errors.New("max packet size cannot be empty")
	}
	packetSize, err := strconv.Atoi(packetSizeText)
	if err != nil || packetSize <= 0 {
		return fmt.Errorf("invalid max packet size: %s", packetSizeText)
	}

	m.config.MulticastAddr = multicast
	m.config.SharedSecret = secret
	m.config.DiscoveryTimeout = discoveryTimeout
	m.config.DTLSConnectTimeout = dtlsTimeout
	m.config.ResponseTimeout = responseTimeout
	m.config.MaxPacketSize = packetSize
	m.config.EnableDebug = m.debugCheck.Checked
	m.config.Logger = m.clientLogger
	return nil
}

func parseDurationWithDefault(value string, fallback time.Duration) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, fmt.Errorf("duration must be greater than zero")
	}
	return d, nil
}

func (m *ClientManager) executeHTTP() {
	addr := strings.TrimSpace(m.httpAddrEntry.Text)
	if addr == "" {
		m.showError(errors.New("target address is required"))
		return
	}
	request := m.httpRequestEntry.Text
	if strings.TrimSpace(request) == "" {
		m.showError(errors.New("http request payload cannot be empty"))
		return
	}
	timeout, err := parseDurationWithDefault(m.httpTimeoutEntry.Text, m.config.ResponseTimeout)
	if err != nil {
		m.showError(fmt.Errorf("invalid http timeout: %w", err))
		return
	}

	m.runOperation("HTTP request", func() error {
		cl, err := m.ensureConnected()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		response, err := cl.DoHTTP(ctx, addr, []byte(request))
		if err != nil {
			return err
		}

		m.runOnMain(func() {
			m.httpResponseEntry.SetText(string(response))
		})
		return nil
	})
}

func (m *ClientManager) executeDNS() {
	name := strings.TrimSpace(m.dnsNameEntry.Text)
	if name == "" {
		m.showError(errors.New("domain name is required"))
		return
	}
	recordType := strings.ToUpper(strings.TrimSpace(m.dnsTypeEntry.Text))
	if recordType == "" {
		recordType = "A"
	}
	dnsType, ok := dns.StringToType[recordType]
	if !ok {
		m.showError(fmt.Errorf("unsupported dns record type %q", recordType))
		return
	}
	timeout, err := parseDurationWithDefault(m.dnsTimeoutEntry.Text, 5*time.Second)
	if err != nil {
		m.showError(fmt.Errorf("invalid dns timeout: %w", err))
		return
	}

	m.runOperation("DNS query", func() error {
		cl, err := m.ensureConnected()
		if err != nil {
			return err
		}

		req := new(dns.Msg)
		req.SetQuestion(dns.Fqdn(name), dnsType)

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		resp, err := cl.QueryDNS(ctx, req)
		if err != nil {
			return err
		}

		m.runOnMain(func() {
			m.dnsOutputEntry.SetText(resp.String())
		})
		return nil
	})
}

func (m *ClientManager) executeTCP() {
	addr := strings.TrimSpace(m.tcpAddrEntry.Text)
	if addr == "" {
		m.showError(errors.New("remote address is required"))
		return
	}
	payload := m.tcpSendEntry.Text
	readTimeout, err := parseDurationWithDefault(m.tcpReadTimeoutEntry.Text, 5*time.Second)
	if err != nil {
		m.showError(fmt.Errorf("invalid tcp read timeout: %w", err))
		return
	}

	m.runOperation("TCP session", func() error {
		cl, err := m.ensureConnected()
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), m.config.ResponseTimeout)
		defer cancel()

		stream, err := cl.DialTCP(ctx, addr)
		if err != nil {
			return err
		}
		defer stream.Close(context.Background())

		if strings.TrimSpace(payload) != "" {
			if err := stream.Write(context.Background(), []byte(payload)); err != nil {
				return err
			}
		}

		if readTimeout <= 0 {
			m.runOnMain(func() {
				m.tcpOutputEntry.SetText("(reading disabled)")
			})
			return nil
		}

		readCtx, cancelRead := context.WithTimeout(context.Background(), readTimeout)
		defer cancelRead()

		var builder strings.Builder
		for {
			data, err := stream.Read(readCtx)
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					m.logf("tcp read timeout reached")
					break
				}
				if errors.Is(err, io.EOF) {
					break
				}
				return err
			}
			if len(data) == 0 {
				continue
			}
			builder.Write(data)
		}

		output := builder.String()
		if output == "" {
			output = "(no data received)"
		}
		m.runOnMain(func() {
			m.tcpOutputEntry.SetText(output)
		})
		return nil
	})
}

func (m *ClientManager) executeUDP() {
	addr := strings.TrimSpace(m.udpAddrEntry.Text)
	if addr == "" {
		m.showError(errors.New("remote address is required"))
		return
	}
	payload := m.udpSendEntry.Text
	readTimeout, err := parseDurationWithDefault(m.udpReadTimeoutEntry.Text, 5*time.Second)
	if err != nil {
		m.showError(fmt.Errorf("invalid udp read timeout: %w", err))
		return
	}

	m.runOperation("UDP session", func() error {
		cl, err := m.ensureConnected()
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), m.config.ResponseTimeout)
		defer cancel()

		session, err := cl.DialUDP(ctx, addr)
		if err != nil {
			return err
		}
		defer session.Close(context.Background())

		if strings.TrimSpace(payload) != "" {
			if err := session.Send(context.Background(), []byte(payload)); err != nil {
				return err
			}
		}

		if readTimeout <= 0 {
			m.runOnMain(func() {
				m.udpOutputEntry.SetText("(reading disabled)")
			})
			return nil
		}

		readCtx, cancelRead := context.WithTimeout(context.Background(), readTimeout)
		defer cancelRead()

		var builder strings.Builder
		first := true
		for {
			data, err := session.Read(readCtx)
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					m.logf("udp read timeout reached")
					break
				}
				if errors.Is(err, io.EOF) {
					break
				}
				return err
			}
			if len(data) == 0 {
				continue
			}
			if !first {
				builder.WriteString("\n")
			}
			builder.Write(data)
			first = false
		}

		output := builder.String()
		if output == "" {
			output = "(no datagrams received)"
		}
		m.runOnMain(func() {
			m.udpOutputEntry.SetText(output)
		})
		return nil
	})
}

func (m *ClientManager) runOperation(name string, op func() error) {
	go func() {
		m.operationMu.Lock()
		m.logf("%s started", name)
		err := op()
		if err != nil {
			m.logf("%s failed: %v", name, err)
			m.operationMu.Unlock()
			m.showError(err)
			return
		}
		m.logf("%s completed successfully", name)
		m.operationMu.Unlock()
	}()
}

func (m *ClientManager) resetClient() error {
	m.operationMu.Lock()
	m.clientMu.Lock()
	cl := m.client
	m.client = nil
	m.clientMu.Unlock()
	m.setConnected(false)
	m.operationMu.Unlock()

	if cl != nil {
		if err := cl.Close(); err != nil {
			m.setHandshake(nil)
			return err
		}
	}
	m.setHandshake(nil)
	return nil
}

func (m *ClientManager) setHandshake(handshake *client.Handshake) {
	var copyHandshake *client.Handshake
	var display string
	if handshake == nil {
		display = "No discovery has been performed yet."
	} else {
		clone := *handshake
		if handshake.SharedKey != nil {
			clone.SharedKey = append([]byte(nil), handshake.SharedKey...)
		}
		if handshake.ServerPublicKey != nil {
			clone.ServerPublicKey = append([]byte(nil), handshake.ServerPublicKey...)
		}
		copyHandshake = &clone
		remote := "(unknown)"
		if handshake.RemoteAddr != nil {
			remote = handshake.RemoteAddr.String()
		}
		display = fmt.Sprintf("Client ID: %x\nSession ID: %x\nShared Key: %x\nServer Public Key: %x\nRemote Address: %s",
			handshake.ClientID,
			handshake.SessionID,
			handshake.SharedKey,
			handshake.ServerPublicKey,
			remote,
		)
	}

	m.stateMu.Lock()
	m.lastHandshake = copyHandshake
	m.stateMu.Unlock()

	m.runOnMain(func() {
		m.handshakeOutput.SetText(display)
	})
}

func (m *ClientManager) setConnected(connected bool) {
	m.stateMu.Lock()
	m.connected = connected
	m.stateMu.Unlock()

	status := "Disconnected"
	if connected {
		status = "Connected"
	}
	m.runOnMain(func() {
		m.statusLabel.SetText(fmt.Sprintf("Status: %s", status))
	})
}

func (m *ClientManager) isConnected() bool {
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	return m.connected
}

func (m *ClientManager) showError(err error) {
	if err == nil {
		return
	}
	m.runOnMain(func() {
		dialog.ShowError(err, m.window)
	})
}

func (m *ClientManager) logf(format string, args ...interface{}) {
	m.appendLog(fmt.Sprintf(format, args...))
}

func (m *ClientManager) appendLog(message string) {
	m.logMu.Lock()
	if message == "" {
		m.logMu.Unlock()
		return
	}
	m.logBuffer = append(m.logBuffer, fmt.Sprintf("[%s] %s", time.Now().Format(time.RFC3339), message))
	if len(m.logBuffer) > 500 {
		m.logBuffer = m.logBuffer[len(m.logBuffer)-500:]
	}
	logs := strings.Join(m.logBuffer, "\n")
	m.logMu.Unlock()

	m.runOnMain(func() {
		m.logOutput.SetText(logs)
		m.logOutput.CursorRow = len(m.logBuffer)
	})
}

func (m *ClientManager) runOnMain(fn func()) {
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

type uiLogWriter struct {
	manager *ClientManager
}

func (w *uiLogWriter) Write(p []byte) (int, error) {
	if w == nil || w.manager == nil {
		return len(p), nil
	}
	text := strings.TrimRight(string(p), "\n")
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		w.manager.appendLog(trimmed)
	}
	return len(p), nil
}
