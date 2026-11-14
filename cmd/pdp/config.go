package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/gfx-labs/pdp/pkg/auth"
	"github.com/gfx-labs/pdp/pkg/config"
	"github.com/gfx-labs/pdp/pkg/gateway"
	"github.com/gfx-labs/pdp/pkg/intercept"
	"github.com/gfx-labs/pdp/pkg/policy"
	"github.com/gfx-labs/pdp/pkg/schema"
)

type combinedAuth struct {
	unix        auth.Authenticator
	spiffe      auth.Authenticator
	transparent bool
}

func (a combinedAuth) Authenticate(r *http.Request) (auth.Identity, error) {
	// A steered connection is never promoted to a Unix or SPIFFE identity.
	if auth.IsTransparent(r.Context()) {
		if a.transparent {
			return auth.Transparent{}.Authenticate(r)
		}
		return auth.Identity{}, auth.ErrUnauthenticated
	}
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
	if c.Transport.UnixSocket == "" && c.Transport.SPIFFE == nil && c.Transport.Transparent == nil {
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
	upstreams := make([]gateway.Upstream, 0, len(l.Config.Upstreams))
	for _, u := range l.Config.Upstreams {
		upstreams = append(upstreams, gateway.Upstream{Host: u.Host, Port: u.Port, Tunnel: u.TLS == "tunnel", Bindings: u.Bindings, Scopes: u.Scopes,
			Plugin: u.Schema, REST: l.REST[u.Schema], GraphQL: l.GraphQL[u.Schema], GraphQLPath: u.GraphQLPath, TokenPaths: u.TokenPaths})
	}
	return gateway.NewSnapshot(gateway.SnapshotConfig{Version: l.Config.Revision, Authenticator: a, Upstreams: upstreams, Policy: l.Policy, Credentials: l.Credentials})
}

// gatewayOptions reads the interception key only when serving. Offline
// validation must work without that deployment secret.
func gatewayOptions(l *config.Loaded, serving bool, logger *log.Logger) (gateway.Options, error) {
	x := l.Config.Limits
	o := gateway.Options{MaxRequestBytes: x.MaxRequestBytes, MaxResponseBytes: x.MaxResponseBytes, MaxHeaderBytes: x.MaxHeaderBytes, MaxConcurrent: x.MaxConcurrent, RequestTimeout: x.RequestTimeout, StreamTimeout: x.StreamTimeout, DisableUpstreamReuse: x.DisableUpstreamReuse, RootCAs: l.RootCAs}
	if i := l.Config.Interception; i != nil && serving {
		authority, err := intercept.Load(i.CertificateFile, i.KeyFile, logger)
		if err != nil {
			return o, err
		}
		o.Interception = authority
	}
	return o, nil
}

// steeredNames are the names DNS answers with the gateway address: every
// upstream host plus the configured patterns, and nothing else.
func steeredNames(c config.Config) []string {
	names := append([]string(nil), c.DNS.Intercept...)
	for _, u := range c.Upstreams {
		names = append(names, u.Host)
	}
	slices.Sort(names)
	return slices.Compact(names)
}

const configFlagUsage = "administrator configuration file, YAML or JSON (default: pdp.yaml, pdp.yml or pdp.json in the working directory)"

// configPath returns the named file, or the one default file present in the
// working directory. Two default files are refused instead of ranked, so an
// administrator cannot edit one while the daemon reads the other.
func configPath(named string) (string, error) {
	if named != "" {
		return named, nil
	}
	var found []string
	for _, name := range []string{"pdp.yaml", "pdp.yml", "pdp.json"} {
		if _, err := os.Stat(name); err == nil {
			found = append(found, name)
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return "", errors.New("no pdp.yaml, pdp.yml or pdp.json in the working directory, use --config")
	}
	return "", errors.New("more than one of pdp.yaml, pdp.yml and pdp.json exists, use --config")
}

func validateCommand(args []string, out, errout io.Writer) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(errout)
	configFlag := fs.String("config", "", configFlagUsage)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("validate accepts no positional arguments")
	}
	path, err := configPath(*configFlag)
	if err != nil {
		return err
	}
	l, err := config.Load(context.Background(), path)
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
	opts, err := gatewayOptions(l, false, nil)
	if err != nil {
		return err
	}
	g, err := gateway.New(s, opts)
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
	configFlag := fs.String("config", "", configFlagUsage)
	inputPath := fs.String("input", "", "trusted pdp.authz/v2 input file, YAML or JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *inputPath == "" {
		return errors.New("usage: pdp explain --config FILE --input FILE")
	}
	path, err := configPath(*configFlag)
	if err != nil {
		return err
	}
	l, err := config.Load(context.Background(), path)
	if err != nil {
		return err
	}
	defer l.Close()
	data, err := readLimited(*inputPath, 1<<20)
	if err != nil {
		return err
	}
	document, err := schema.DecodeDocument(data)
	if err != nil {
		return errors.New("authorization input must be one valid YAML or JSON document")
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return errors.New("invalid trusted authorization input")
	}
	var input policy.Input
	dec := json.NewDecoder(bytes.NewReader(encoded))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(&input); err != nil {
		return errors.New("invalid trusted authorization input")
	}
	decision, err := l.Policy.Evaluate(context.Background(), input)
	if err != nil {
		return errors.New("authorization evaluation failed")
	}
	return printJSON(out, decision)
}
