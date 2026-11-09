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
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"syscall"
	"time"

	"github.com/gfx-labs/pdp/pkg/auth"
	"github.com/gfx-labs/pdp/pkg/config"
	"github.com/gfx-labs/pdp/pkg/gateway"
)

func runtimeAuth(c config.Config, source *auth.SPIFFE) (auth.Authenticator, error) {
	var a combinedAuth
	if c.Transport.UnixSocket != "" {
		u, err := auth.NewUnix(c.Identities)
		if err != nil {
			return nil, err
		}
		a.unix = u
	}
	if c.Transport.SPIFFE != nil {
		if source == nil {
			return nil, errors.New("SPIFFE source is unavailable")
		}
		s, err := source.WithPrincipals(c.Transport.SPIFFE.Principals)
		if err != nil {
			return nil, err
		}
		a.spiffe = s
	}
	return a, nil
}

// Transport changes require restart. Principal mappings belong to snapshots and
// may change without replacing listeners, TLS sources or open connections.
func sameRuntime(a, b config.Config) bool {
	if a.Transport.UnixSocket != b.Transport.UnixSocket || a.Transport.SocketMode != b.Transport.SocketMode || a.CAFile != b.CAFile || !reflect.DeepEqual(a.Limits, b.Limits) {
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
	path := fs.String("config", "pdp.yaml", "administrator configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("serve accepts no positional arguments")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	l, err := config.Load(ctx, *path)
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
		source, err = auth.NewSPIFFE(initCtx, s.WorkloadAPI, s.Principals)
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
	opts := gatewayOptions(l)
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
	servers := make([]*http.Server, 0, len(listeners))
	serverErrors := make(chan error, len(listeners))
	for _, listener := range listeners {
		server := gateway.NewHTTPServer(listener.Addr().String(), g)
		servers = append(servers, server)
		go func(server *http.Server, listener net.Listener) { serverErrors <- server.Serve(listener) }(server, listener)
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
			next, err := config.Load(ctx, *path)
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
				logger.Print(`{"event":"reload_rejected","reason":"invalid_identity_mapping"}`)
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
