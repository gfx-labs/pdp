package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/gfx-labs/pdp/pkg/auth"
)

const gatewayDialTimeout = 10 * time.Second

// loopbackListenAddress refuses anything but a loopback IP and a fixed port.
// Every process that can reach the port is forwarded under the workload's SVID.
func loopbackListenAddress(address string) error {
	parsed, err := netip.ParseAddrPort(address)
	if err != nil || !parsed.Addr().IsLoopback() || parsed.Port() == 0 {
		return errors.New("--listen must be a loopback IP address with a port, such as 127.0.0.1:3128, because every process that can reach it acts as the workload")
	}
	return nil
}

func forwardCommand(args []string, out, errout io.Writer) error {
	fs := flag.NewFlagSet("forward", flag.ContinueOnError)
	fs.SetOutput(errout)
	listen := fs.String("listen", "", "loopback TCP address to accept on, for example 127.0.0.1:3128")
	workloadAPI := fs.String("workload-api", "", "SPIFFE Workload API endpoint, unix:///PATH")
	gateway := fs.String("gateway", "", "PDP SPIFFE listener, HOST:PORT")
	gatewayID := fs.String("gateway-id", "", "SPIFFE ID the gateway must present")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *listen == "" || *workloadAPI == "" || *gateway == "" || *gatewayID == "" {
		return errors.New("usage: pdp forward --listen 127.0.0.1:PORT --workload-api unix:///PATH --gateway HOST:PORT --gateway-id SPIFFE_ID")
	}
	if err := loopbackListenAddress(*listen); err != nil {
		return err
	}
	if !strings.HasPrefix(*workloadAPI, "unix:///") {
		return errors.New("--workload-api must start with unix:///")
	}
	if host, port, err := net.SplitHostPort(*gateway); err != nil || host == "" || port == "" {
		return errors.New("--gateway must be HOST:PORT")
	}
	id, err := spiffeid.FromString(*gatewayID)
	if err != nil {
		return errors.New("--gateway-id must be a SPIFFE ID")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	initCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	source, err := auth.NewSPIFFE(initCtx, *workloadAPI)
	cancel()
	if err != nil {
		return err
	}
	defer source.Close()
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return errors.New("cannot listen on --listen address")
	}
	if err := printJSON(out, struct {
		State string `json:"state"`
	}{"ready"}); err != nil {
		listener.Close()
		return err
	}
	return forward(ctx, listener.(*net.TCPListener), *gateway, source.ClientTLSConfig(id), log.New(errout, "", 0))
}

// forward relays each accepted connection over its own mTLS connection to the
// gateway until ctx ends. It reads no HTTP, so the proxy conversation,
// including CONNECT, reaches the gateway as the client wrote it.
func forward(ctx context.Context, listener *net.TCPListener, gateway string, config *tls.Config, logger *log.Logger) error {
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	defer listener.Close()
	var connections sync.WaitGroup
	defer connections.Wait()
	dialer := &tls.Dialer{Config: config}
	for {
		client, err := listener.AcceptTCP()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errors.New("forward listener failed")
		}
		connections.Go(func() {
			defer client.Close()
			dialCtx, cancel := context.WithTimeout(ctx, gatewayDialTimeout)
			conn, err := dialer.DialContext(dialCtx, "tcp", gateway)
			cancel()
			if err != nil {
				if ctx.Err() == nil {
					// A dial or handshake error names addresses and SPIFFE IDs, never key material.
					logger.Printf("forward: gateway connection failed: %v", err)
				}
				return
			}
			defer conn.Close()
			stop := context.AfterFunc(ctx, func() { client.Close(); conn.Close() })
			defer stop()
			relay(client, conn.(*tls.Conn))
		})
	}
}

// relay copies both directions. A clean end of one direction is passed on as a
// half-close, so a client that has finished sending still receives the rest of
// the response. An error in either direction closes both connections.
func relay(client *net.TCPConn, gateway *tls.Conn) {
	closeBoth := func() { client.Close(); gateway.Close() }
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		if _, err := io.Copy(gateway, client); err != nil || gateway.CloseWrite() != nil {
			closeBoth()
		}
	}()
	if _, err := io.Copy(client, gateway); err != nil || client.CloseWrite() != nil {
		closeBoth()
	}
	<-sent
}
