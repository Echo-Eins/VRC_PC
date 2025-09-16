package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"vpn-relay/client"

	"github.com/miekg/dns"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	defaults := client.DefaultConfig()

	multicast := flag.String("multicast", defaults.MulticastAddr, "Multicast discovery address")
	sharedSecret := flag.String("psk", defaults.SharedSecret, "Pre-shared key for DTLS authentication")
	discoveryTimeout := flag.Duration("discovery-timeout", defaults.DiscoveryTimeout, "Discovery timeout")
	dtlsTimeout := flag.Duration("dtls-timeout", defaults.DTLSConnectTimeout, "DTLS dial timeout")
	responseTimeout := flag.Duration("response-timeout", defaults.ResponseTimeout, "Application response timeout")
	debug := flag.Bool("debug", false, "Enable verbose debug logging")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [global options] <command> [args]\n", os.Args[0])
		fmt.Fprintln(flag.CommandLine.Output(), "Commands:")
		fmt.Fprintln(flag.CommandLine.Output(), "  discover             Perform multicast discovery and print session information")
		fmt.Fprintln(flag.CommandLine.Output(), "  http                 Execute a single HTTP request through the relay")
		fmt.Fprintln(flag.CommandLine.Output(), "  dns                  Resolve a DNS record via the relay")
		fmt.Fprintln(flag.CommandLine.Output(), "  tcp                  Open a TCP stream and optionally exchange data")
		fmt.Fprintln(flag.CommandLine.Output(), "  udp                  Open a UDP association and exchange datagrams")
		fmt.Fprintln(flag.CommandLine.Output(), "\nGlobal options:")
		flag.PrintDefaults()
	}

	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	cfg := client.Config{
		MulticastAddr:      *multicast,
		SharedSecret:       *sharedSecret,
		EnableDebug:        *debug,
		DiscoveryTimeout:   *discoveryTimeout,
		DTLSConnectTimeout: *dtlsTimeout,
		ResponseTimeout:    *responseTimeout,
	}

	cl, err := client.New(cfg)
	if err != nil {
		fatal(fmt.Errorf("create client: %w", err))
	}
	defer cl.Close()

	command := args[0]
	cmdArgs := args[1:]

	var runErr error
	switch command {
	case "discover":
		runErr = handleDiscover(ctx, cl)
	case "http":
		runErr = handleHTTP(ctx, cl, cmdArgs)
	case "dns":
		runErr = handleDNS(ctx, cl, cmdArgs)
	case "tcp":
		runErr = handleTCP(ctx, cl, cmdArgs)
	case "udp":
		runErr = handleUDP(ctx, cl, cmdArgs)
	default:
		flag.Usage()
		fatal(fmt.Errorf("unknown command %q", command))
	}

	if runErr != nil {
		fatal(runErr)
	}
}

func handleDiscover(ctx context.Context, cl *client.Client) error {
	handshake, err := cl.Discover(ctx)
	if err != nil {
		return fmt.Errorf("discovery failed: %w", err)
	}

	fmt.Printf("Client ID: %x\n", handshake.ClientID)
	fmt.Printf("Session ID: %x\n", handshake.SessionID)
	if handshake.RemoteAddr != nil {
		fmt.Printf("DTLS endpoint: %s\n", handshake.RemoteAddr)
	}
	fmt.Printf("Shared key: %x\n", handshake.SharedKey)
	fmt.Printf("Server public key: %x\n", handshake.ServerPublicKey)
	return nil
}

func handleHTTP(ctx context.Context, cl *client.Client, args []string) error {
	fs := flag.NewFlagSet("http", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		addr        = fs.String("addr", "", "Target HTTP server address (host:port)")
		requestFile = fs.String("request-file", "", "Path to a file containing the raw HTTP request")
		requestData = fs.String("request", "", "Inline raw HTTP request payload")
		timeout     = fs.Duration("timeout", 30*time.Second, "Overall timeout for the HTTP exchange")
	)

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *addr == "" {
		return errors.New("--addr is required")
	}

	body, err := readInputData(*requestData, *requestFile)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return errors.New("HTTP request payload cannot be empty")
	}

	opCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	if _, err := cl.Discover(opCtx); err != nil {
		return fmt.Errorf("discovery failed: %w", err)
	}
	if err := cl.Connect(opCtx); err != nil {
		return fmt.Errorf("connect failed: %w", err)
	}

	response, err := cl.DoHTTP(opCtx, *addr, body)
	if err != nil {
		return err
	}

	if _, err := os.Stdout.Write(response); err != nil {
		return fmt.Errorf("write response: %w", err)
	}
	return nil
}

func handleDNS(ctx context.Context, cl *client.Client, args []string) error {
	fs := flag.NewFlagSet("dns", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		name    = fs.String("name", "", "Domain name to resolve")
		qtype   = fs.String("type", "A", "Record type (A, AAAA, MX, TXT, ...)")
		timeout = fs.Duration("timeout", 10*time.Second, "Timeout for the DNS request")
	)

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("--name is required")
	}

	recordType := strings.ToUpper(*qtype)
	dnsType, ok := dns.StringToType[recordType]
	if !ok {
		return fmt.Errorf("unsupported DNS record type %q", recordType)
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(*name), dnsType)

	opCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	if _, err := cl.Discover(opCtx); err != nil {
		return fmt.Errorf("discovery failed: %w", err)
	}
	if err := cl.Connect(opCtx); err != nil {
		return fmt.Errorf("connect failed: %w", err)
	}

	response, err := cl.QueryDNS(opCtx, msg)
	if err != nil {
		return err
	}

	fmt.Println(response.String())
	return nil
}

func handleTCP(ctx context.Context, cl *client.Client, args []string) error {
	fs := flag.NewFlagSet("tcp", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		addr        = fs.String("addr", "", "Target TCP address (host:port)")
		sendFile    = fs.String("send-file", "", "File containing data to send after connection")
		sendData    = fs.String("send", "", "Inline data to send after connection")
		readTimeout = fs.Duration("read-timeout", 5*time.Second, "How long to wait for data before closing")
	)

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *addr == "" {
		return errors.New("--addr is required")
	}

	if _, err := cl.Discover(ctx); err != nil {
		return fmt.Errorf("discovery failed: %w", err)
	}
	if err := cl.Connect(ctx); err != nil {
		return fmt.Errorf("connect failed: %w", err)
	}

	stream, err := cl.DialTCP(ctx, *addr)
	if err != nil {
		return err
	}
	defer func() {
		if err := stream.Close(context.Background()); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to close tcp stream: %v\n", err)
		}
	}()

	payload, err := readInputData(*sendData, *sendFile)
	if err != nil {
		return err
	}
	if len(payload) > 0 {
		if err := stream.Write(ctx, payload); err != nil {
			return fmt.Errorf("send payload: %w", err)
		}
	}

	if *readTimeout > 0 {
		readCtx, cancel := context.WithTimeout(ctx, *readTimeout)
		defer cancel()

		for {
			data, err := stream.Read(readCtx)
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					fmt.Fprintln(os.Stderr, "read timeout reached")
					break
				}
				if errors.Is(err, io.EOF) {
					break
				}
				return fmt.Errorf("tcp read: %w", err)
			}
			if len(data) == 0 {
				continue
			}
			if _, err := os.Stdout.Write(data); err != nil {
				return fmt.Errorf("write output: %w", err)
			}
		}
	}

	return nil
}

func handleUDP(ctx context.Context, cl *client.Client, args []string) error {
	fs := flag.NewFlagSet("udp", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		addr        = fs.String("addr", "", "Target UDP address (host:port)")
		sendFile    = fs.String("send-file", "", "File containing datagram payload to send")
		sendData    = fs.String("send", "", "Inline datagram payload to send")
		readTimeout = fs.Duration("read-timeout", 5*time.Second, "How long to wait for a datagram before closing")
	)

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *addr == "" {
		return errors.New("--addr is required")
	}

	if _, err := cl.Discover(ctx); err != nil {
		return fmt.Errorf("discovery failed: %w", err)
	}
	if err := cl.Connect(ctx); err != nil {
		return fmt.Errorf("connect failed: %w", err)
	}

	session, err := cl.DialUDP(ctx, *addr)
	if err != nil {
		return err
	}
	defer func() {
		if err := session.Close(context.Background()); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to close udp session: %v\n", err)
		}
	}()

	payload, err := readInputData(*sendData, *sendFile)
	if err != nil {
		return err
	}
	if len(payload) > 0 {
		if err := session.Send(ctx, payload); err != nil {
			return fmt.Errorf("send datagram: %w", err)
		}
	}

	if *readTimeout > 0 {
		readCtx, cancel := context.WithTimeout(ctx, *readTimeout)
		defer cancel()

		for {
			data, err := session.Read(readCtx)
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					fmt.Fprintln(os.Stderr, "read timeout reached")
					break
				}
				if errors.Is(err, io.EOF) {
					break
				}
				return fmt.Errorf("udp read: %w", err)
			}
			if len(data) == 0 {
				continue
			}
			if _, err := os.Stdout.Write(data); err != nil {
				return fmt.Errorf("write output: %w", err)
			}
			os.Stdout.WriteString("\n")
		}
	}

	return nil
}

func readInputData(inline string, filePath string) ([]byte, error) {
	switch {
	case filePath != "":
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("read file %s: %w", filePath, err)
		}
		return data, nil
	case inline != "":
		return []byte(inline), nil
	default:
		info, err := os.Stdin.Stat()
		if err != nil {
			return nil, fmt.Errorf("stat stdin: %w", err)
		}
		if (info.Mode() & os.ModeCharDevice) != 0 {
			return nil, nil
		}
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		return data, nil
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	os.Exit(1)
}
