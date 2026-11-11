package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/gfx-labs/pdp/pkg/auth"
	"github.com/gfx-labs/pdp/pkg/config"
	"github.com/gfx-labs/pdp/pkg/gateway"
	"github.com/gfx-labs/pdp/pkg/policy"
)

type combinedAuth struct {
	unix   auth.Authenticator
	spiffe auth.Authenticator
}

func (a combinedAuth) Authenticate(r *http.Request) (auth.Identity, error) {
	if r.TLS != nil {
		if a.spiffe != nil {
			return a.spiffe.Authenticate(r)
		}
		return auth.Identity{}, auth.ErrUnauthenticated
	}
	if a.unix != nil {
		return a.unix.Authenticate(r)
	}
	return auth.Identity{}, auth.ErrUnauthenticated
}

func validateTransport(c config.Config) error {
	if c.Transport.UnixSocket == "" && c.Transport.SPIFFE == nil {
		return errors.New("at least one listening transport is required")
	}
	mode, err := strconv.ParseUint(c.Transport.SocketMode, 8, 32)
	if err != nil || mode == 0 || mode & ^uint64(0770) != 0 || mode&0007 != 0 {
		return errors.New("socket_mode must be a private octal mode such as 0600 or 0660")
	}
	if s := c.Transport.SPIFFE; s != nil {
		if s.Address == "" || !strings.HasPrefix(s.WorkloadAPI, "unix:///") {
			return errors.New("invalid SPIFFE transport")
		}
	}
	return nil
}

func snapshot(l *config.Loaded, a auth.Authenticator) (*gateway.Snapshot, error) {
	routes := make([]gateway.Route, 0, len(l.Config.Routes))
	for _, r := range l.Config.Routes {
		routes = append(routes, gateway.Route{Provider: r.Provider, Binding: r.Binding, UpstreamURL: r.UpstreamURL, Scopes: r.Scopes, REST: l.REST[r.Schema], GraphQL: l.GraphQL[r.Schema]})
	}
	return gateway.NewSnapshot(gateway.SnapshotConfig{Version: l.Config.Revision, Authenticator: a, Routes: routes, Policy: l.Policy, Credentials: l.Credentials})
}

func gatewayOptions(l *config.Loaded) gateway.Options {
	x := l.Config.Limits
	return gateway.Options{MaxRequestBytes: x.MaxRequestBytes, MaxResponseBytes: x.MaxResponseBytes, MaxHeaderBytes: x.MaxHeaderBytes, MaxConcurrent: x.MaxConcurrent, RequestTimeout: x.RequestTimeout, RootCAs: l.RootCAs}
}

func validateCommand(args []string, out, errout io.Writer) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(errout)
	path := fs.String("config", "pdp.json", "administrator configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("validate accepts no positional arguments")
	}
	l, err := config.Load(context.Background(), *path)
	if err != nil {
		return err
	}
	defer l.Close()
	if err := validateTransport(l.Config); err != nil {
		return err
	}
	// The snapshot constructor validates routing and scope bindings. This
	// authenticator intentionally cannot authenticate an offline request.
	s, err := snapshot(l, combinedAuth{})
	if err != nil {
		return err
	}
	g, err := gateway.New(s, gatewayOptions(l))
	if err != nil {
		return err
	}
	g.Close()
	return printJSON(out, struct {
		Valid       bool                `json:"valid"`
		Revision    string              `json:"revision"`
		Diagnostics []policy.Diagnostic `json:"diagnostics"`
	}{true, l.Config.Revision, l.Policy.Diagnostics()})
}

func explainCommand(args []string, out, errout io.Writer) error {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	fs.SetOutput(errout)
	path := fs.String("config", "pdp.json", "administrator configuration file")
	inputPath := fs.String("input", "", "trusted pdp.authz/v1 input JSON file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *inputPath == "" {
		return errors.New("usage: pdp explain --config FILE --input FILE")
	}
	l, err := config.Load(context.Background(), *path)
	if err != nil {
		return err
	}
	defer l.Close()
	data, err := readLimited(*inputPath, 1<<20)
	if err != nil {
		return err
	}
	var input policy.Input
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(&input); err != nil {
		return errors.New("invalid trusted authorization input")
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("authorization input must contain exactly one JSON object")
	}
	decision, err := l.Policy.Evaluate(context.Background(), input)
	if err != nil {
		return errors.New("authorization evaluation failed")
	}
	return printJSON(out, decision)
}
