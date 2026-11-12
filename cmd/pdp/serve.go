package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"reflect"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/gfx-labs/pdp/pkg/auth"
	"github.com/gfx-labs/pdp/pkg/config"
	"github.com/gfx-labs/pdp/pkg/gateway"
	"github.com/gfx-labs/pdp/pkg/steer"
)

func runtimeAuth(c config.Config, source *auth.SPIFFE) (auth.Authenticator, error) {
	a := combinedAuth{transparent: c.Transport.Transparent != nil}
	if c.Transport.UnixSocket != "" {
		a.unix = auth.NewUnix()
	}
	if c.Transport.SPIFFE != nil {
		if source == nil {
			return nil, errors.New("SPIFFE source is unavailable")
		}
		a.spiffe = source
	}
	return a, nil
}

// Transport, interception and DNS changes require restart. Policy, upstreams and
// credentials change with a snapshot without replacing listeners or open
// connections. The DNS server is not part of a snapshot, so a reload that
// changes which names it intercepts is rejected.
func sameRuntime(a, b config.Config) bool {
	if a.Transport.UnixSocket != b.Transport.UnixSocket || a.Transport.SocketMode != b.Transport.SocketMode || a.CAFile != b.CAFile || !reflect.DeepEqual(a.Limits, b.Limits) {
		return false
	}
	if !reflect.DeepEqual(a.Transport.Transparent, b.Transport.Transparent) || !reflect.DeepEqual(a.Interception, b.Interception) || !reflect.DeepEqual(a.DNS, b.DNS) {
		return false
	}
	if a.DNS != nil && !slices.Equal(steeredNames(a), steeredNames(b)) {
		return false
	}
	as, bs := a.Transport.SPIFFE, b.Transport.SPIFFE
	if (as == nil) != (bs == nil) {
		return false
	}
	return as == nil || (as.Address == bs.Address && as.WorkloadAPI == bs.WorkloadAPI)
}

func serveCommand(args []string, out, errout io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(errout)
	configFlag := fs.String("config", "", configFlagUsage)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("serve accepts no positional arguments")
	}
	// Resolved once, so a reload reads the file the daemon started from.
	path, err := configPath(*configFlag)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	l, err := config.Load(ctx, path)
	if err != nil {
		return err
	}
	defer func() { l.Close() }()
	if err := validateTransport(l.Config); err != nil {
		return err
	}
	var source *auth.SPIFFE
	if s := l.Config.Transport.SPIFFE; s != nil {
		initCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		source, err = auth.NewSPIFFE(initCtx, s.WorkloadAPI)
		cancel()
		if err != nil {
			return err
		}
		defer source.Close()
	}
	a, err := runtimeAuth(l.Config, source)
	if err != nil {
		return err
	}
	s, err := snapshot(l, a)
	if err != nil {
		return err
	}
	logger := log.New(errout, "", 0)
	opts, err := gatewayOptions(l, true)
	if err != nil {
		return err
	}
	opts.Audit = func(event gateway.AuditEvent) {
		b, err := json.Marshal(event)
		if err == nil {
			logger.Print(string(b))
		}
	}
	g, err := gateway.New(s, opts)
	if err != nil {
		return err
	}
	defer g.Close()
	var listeners []net.Listener
	defer func() {
		for _, listener := range listeners {
			listener.Close()
		}
	}()
	inherited, active, err := auth.InheritedUnixListener()
	if err != nil {
		return err
	}
	if active {
		if l.Config.Transport.UnixSocket == "" {
			inherited.Close()
			return errors.New("socket activation requires the Unix transport")
		}
		if inherited.Addr().String() != l.Config.Transport.UnixSocket {
			inherited.Close()
			return errors.New("inherited socket does not match configured path")
		}
		listeners = append(listeners, inherited)
	} else if l.Config.Transport.UnixSocket != "" {
		mode, _ := strconv.ParseUint(l.Config.Transport.SocketMode, 8, 32)
		listener, err := auth.ListenUnix(l.Config.Transport.UnixSocket, os.FileMode(mode))
		if err != nil {
			return err
		}
		listeners = append(listeners, listener)
	}
	if source != nil {
		listener, err := net.Listen("tcp", l.Config.Transport.SPIFFE.Address)
		if err != nil {
			return errors.New("cannot listen on SPIFFE transport")
		}
		listeners = append(listeners, tls.NewListener(listener, source.TLSConfig()))
	}
	servers := make([]*http.Server, 0, len(listeners)+2)
	serverErrors := make(chan error, len(listeners)+3)
	for _, listener := range listeners {
		server := gateway.NewHTTPServer(listener.Addr().String(), g)
		servers = append(servers, server)
		go func(server *http.Server, listener net.Listener) { serverErrors <- server.Serve(listener) }(server, listener)
	}
	if t := l.Config.Transport.Transparent; t != nil {
		for _, address := range []string{t.HTTP, t.HTTPS} {
			if address == "" {
				continue
			}
			listener, err := net.Listen("tcp", address)
			if err != nil {
				return errors.New("cannot listen on transparent transport")
			}
			if address == t.HTTPS {
				tlsConfig, err := g.TransparentTLSConfig()
				if err != nil {
					listener.Close()
					return err
				}
				listener = tls.NewListener(listener, tlsConfig)
			}
			listeners = append(listeners, listener)
			server := gateway.NewTransparentServer(address, g)
			servers = append(servers, server)
			go func(server *http.Server, listener net.Listener) { serverErrors <- server.Serve(listener) }(server, listener)
		}
	}
	if d := l.Config.DNS; d != nil {
		address, err := netip.ParseAddr(d.Address)
		if err != nil {
			return errors.New("dns address must be the gateway IP address")
		}
		resolver, err := steer.New(steer.Config{Address: address, Names: steeredNames(l.Config), ForwardTo: d.Resolver})
		if err != nil {
			return err
		}
		packets, err := net.ListenPacket("udp", d.Listen)
		if err != nil {
			return errors.New("cannot listen on DNS transport")
		}
		defer packets.Close()
		go func() {
			if err := resolver.Serve(packets); err != nil && !errors.Is(err, net.ErrClosed) {
				serverErrors <- err
			}
		}()
	}
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		for _, server := range servers {
			if err := server.Shutdown(shutdown); err != nil {
				server.Close()
			}
		}
	}()
	if err := printJSON(out, struct {
		State    string `json:"state"`
		Revision string `json:"revision"`
	}{"ready", l.Config.Revision}); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-serverErrors:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				return errors.New("gateway listener failed")
			}
			return nil
		case <-hup:
			next, err := config.Load(ctx, path)
			if err != nil {
				logger.Print(`{"event":"reload_rejected","reason":"invalid_configuration"}`)
				continue
			}
			trustChanged := (l.RootCAs == nil) != (next.RootCAs == nil)
			if l.RootCAs != nil && next.RootCAs != nil && !l.RootCAs.Equal(next.RootCAs) {
				trustChanged = true
			}
			if err = validateTransport(next.Config); err != nil || !sameRuntime(l.Config, next.Config) || trustChanged || next.Config.Revision == l.Config.Revision {
				next.Close()
				logger.Print(`{"event":"reload_rejected","reason":"invalid_transport_or_revision"}`)
				continue
			}
			a, err := runtimeAuth(next.Config, source)
			if err != nil {
				next.Close()
				logger.Print(`{"event":"reload_rejected","reason":"spiffe_source_unavailable"}`)
				continue
			}
			s, err := snapshot(next, a)
			if err != nil {
				next.Close()
				logger.Print(`{"event":"reload_rejected","reason":"invalid_snapshot"}`)
				continue
			}
			if err = g.Reload(s); err != nil {
				next.Close()
				logger.Print(`{"event":"reload_rejected","reason":"publication_failed"}`)
				continue
			}
			l = next
			ack, _ := json.Marshal(struct {
				Event    string `json:"event"`
				Revision string `json:"revision"`
			}{"reload_applied", next.Config.Revision})
			logger.Print(string(ack))
		}
	}
}
