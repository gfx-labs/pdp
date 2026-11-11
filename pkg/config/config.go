// Package config loads administrator-owned snapshots. It never obtains provider
// credentials, contacts an upstream, or modifies the active runtime on failure.
package config

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gfx-labs/pdp/pkg/credential"
	"github.com/gfx-labs/pdp/pkg/policy"
	"github.com/gfx-labs/pdp/pkg/schema"
)

const Version = "pdp.config/v3"
const MaxConfigBytes = 4 << 20
const MaxSchemaBytes = 4 << 20
const MaxPolicyBytes = 4 << 20
const MaxAdapterBytes = 1 << 20

// Relative paths are resolved against the configuration file, never cwd.
type Config struct {
	Version      string            `json:"version"`
	Revision     string            `json:"revision"`
	CAFile       string            `json:"ca_file,omitempty"`
	Limits       Limits            `json:"limits,omitempty"`
	Transport    Transport         `json:"transport"`
	Interception *Interception     `json:"interception,omitempty"`
	DNS          *DNS              `json:"dns,omitempty"`
	Schemas      map[string]Schema `json:"schemas,omitempty"`
	Upstreams    []Upstream        `json:"upstreams,omitempty"`
	Credentials  credential.Config `json:"credentials"`
	Policy       Policy            `json:"policy"`
}

// Policy names administrator-authored Rego modules and optional OPA data.
// Data accepts at most one JSON object file, without merging or rewriting it.
type Policy struct {
	Modules []string `json:"modules"`
	Data    []string `json:"data,omitempty"`
}

type Limits struct {
	MaxRequestBytes  int64         `json:"max_request_bytes,omitempty"`
	MaxResponseBytes int64         `json:"max_response_bytes,omitempty"`
	MaxHeaderBytes   int           `json:"max_header_bytes,omitempty"`
	MaxConcurrent    int           `json:"max_concurrent,omitempty"`
	RequestTimeout   time.Duration `json:"request_timeout,omitempty"`
	StreamTimeout    time.Duration `json:"stream_timeout,omitempty"`
}

type Transport struct {
	UnixSocket  string       `json:"unix_socket,omitempty"`
	SocketMode  string       `json:"socket_mode,omitempty"`
	SPIFFE      *SPIFFE      `json:"spiffe,omitempty"`
	Transparent *Transparent `json:"transparent,omitempty"`
}

// Transparent listeners serve DNS-steered callers, identified only by source
// address. The TLS listener needs the interception CA.
type Transparent struct {
	HTTP  string `json:"http,omitempty"`
	HTTPS string `json:"https,omitempty"`
}

// Interception names the CA that signs leaf certificates for CONNECT and
// transparent TLS. CertificateFile holds the CA, then any intermediates below
// the root that workloads trust.
type Interception struct {
	CertificateFile string `json:"certificate_file"`
	KeyFile         string `json:"key_file"`
}

// DNS answers with Address for upstream hosts and Intercept patterns only.
// Unlisted is "forward" (needs Resolver) or "refuse".
type DNS struct {
	Listen    string   `json:"listen"`
	Address   string   `json:"address"`
	Intercept []string `json:"intercept,omitempty"`
	Unlisted  string   `json:"unlisted,omitempty"`
	Resolver  string   `json:"resolver,omitempty"`
}

type SPIFFE struct {
	Address     string `json:"address"`
	WorkloadAPI string `json:"workload_api"`
}

type Schema struct {
	Protocol string `json:"protocol"`
	File     string `json:"file"`
}

// Upstream attaches a credential, schema or TLS mode to one destination. It
// does not allow the destination. Only policy does.
type Upstream struct {
	Host string `json:"host"`
	Port int    `json:"port,omitempty"`
	// TLS is "intercept" (default) or "tunnel".
	TLS string `json:"tls,omitempty"`
	// Binding is shorthand for one entry in Bindings.
	Binding     string   `json:"binding,omitempty"`
	Bindings    []string `json:"bindings,omitempty"`
	Schema      string   `json:"schema,omitempty"`
	GraphQLPath string   `json:"graphql_path,omitempty"`
	TokenPaths  []string `json:"token_paths,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
}

// Loaded owns a complete prospective snapshot, including its credential cache.
// Close is called only when the snapshot has stopped serving requests.
type Loaded struct {
	Config      Config
	Policy      *policy.Engine
	Credentials *credential.Manager
	REST        map[string]*schema.RESTSchema
	GraphQL     map[string]*schema.GraphQLSchema
	Catalogs    map[string]schema.Catalog
	RootCAs     *x509.CertPool
}

func (l *Loaded) Close() {
	if l != nil && l.Credentials != nil {
		l.Credentials.Close()
	}
}

func readFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open configuration dependency")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("configuration dependency must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("configuration dependency exceeds limit or is unreadable")
	}
	return data, nil
}

func resolve(base, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(base, path)
}

// decode accepts only strict JSON. Duration conversion is limited to typed
// runtime limits, never arbitrary provider parameters or authored policy data.
func decode(data []byte, target any) error {
	raw, err := schema.DecodeJSON(data)
	if err != nil {
		return errors.New("invalid configuration JSON")
	}
	root, ok := raw.(map[string]any)
	if !ok {
		return errors.New("configuration must be a JSON object")
	}
	for _, path := range [][]string{{"limits", "request_timeout"}, {"limits", "stream_timeout"}, {"credentials", "limits", "timeout"}, {"credentials", "limits", "expiry_margin"}} {
		if err := normalizeDuration(root, path); err != nil {
			return err
		}
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return errors.New("invalid configuration JSON")
	}
	jd := json.NewDecoder(bytes.NewReader(b))
	jd.DisallowUnknownFields()
	jd.UseNumber()
	if err := jd.Decode(target); err != nil {
		return errors.New("invalid configuration field or value")
	}
	return nil
}

func normalizeDuration(root map[string]any, path []string) error {
	for _, key := range path[:len(path)-1] {
		next, ok := root[key].(map[string]any)
		if !ok {
			return nil
		}
		root = next
	}
	key := path[len(path)-1]
	value, exists := root[key]
	if !exists {
		return nil
	}
	switch value := value.(type) {
	case string:
		d, err := time.ParseDuration(value)
		if err != nil {
			return errors.New("invalid configuration duration")
		}
		root[key] = int64(d)
	case json.Number:
		if _, err := value.Int64(); err != nil {
			return errors.New("configuration duration must be integer nanoseconds or a duration string")
		}
	default:
		return errors.New("configuration duration must be integer nanoseconds or a duration string")
	}
	return nil
}

func loadPolicy(base, revision string, files Policy) (policy.Config, error) {
	c := policy.Config{Revision: revision, Modules: make(map[string]string), Data: make(map[string]any)}
	if len(files.Modules) == 0 || len(files.Data) > 1 {
		return c, errors.New("policy requires Rego modules and at most one JSON data file")
	}
	remaining := int64(MaxPolicyBytes)
	for _, path := range files.Modules {
		if path == "" || filepath.Ext(path) != ".rego" {
			return c, errors.New("policy module must name a Rego file")
		}
		path = filepath.Clean(resolve(base, path))
		if _, exists := c.Modules[path]; exists {
			return c, errors.New("duplicate policy module file")
		}
		data, err := readFile(path, remaining)
		if err != nil {
			return c, err
		}
		remaining -= int64(len(data))
		c.Modules[path] = string(data)
	}
	if len(files.Data) == 1 {
		if files.Data[0] == "" {
			return c, errors.New("policy data file is required")
		}
		data, err := readFile(resolve(base, files.Data[0]), MaxPolicyBytes)
		if err != nil {
			return c, err
		}
		value, err := schema.DecodeJSON(data)
		if err != nil {
			return c, errors.New("invalid policy data JSON")
		}
		var ok bool
		c.Data, ok = value.(map[string]any)
		if !ok {
			return c, errors.New("policy data must be a JSON object")
		}
	}
	return c, nil
}

func Load(ctx context.Context, path string) (_ *Loaded, err error) {
	path, err = filepath.Abs(path)
	if err != nil {
		return nil, errors.New("invalid configuration path")
	}
	data, err := readFile(path, MaxConfigBytes)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := decode(data, &c); err != nil {
		return nil, err
	}
	if c.Version != Version || c.Revision == "" || strings.ContainsAny(c.Revision, "\r\n\x00") {
		return nil, errors.New("configuration version or revision is invalid")
	}
	base := filepath.Dir(path)
	c.Transport.UnixSocket = resolve(base, c.Transport.UnixSocket)
	if c.Interception != nil {
		if c.Interception.CertificateFile == "" || c.Interception.KeyFile == "" {
			return nil, errors.New("interception requires certificate_file and key_file")
		}
		c.Interception.CertificateFile = resolve(base, c.Interception.CertificateFile)
		c.Interception.KeyFile = resolve(base, c.Interception.KeyFile)
	}
	if t := c.Transport.Transparent; t != nil {
		if t.HTTP == "" && t.HTTPS == "" {
			return nil, errors.New("transparent transport needs an http or https address")
		}
		if t.HTTPS != "" && c.Interception == nil {
			return nil, errors.New("transparent https requires interception")
		}
	}
	if d := c.DNS; d != nil {
		if d.Unlisted == "" {
			d.Unlisted = "forward"
		}
		if d.Listen == "" || (d.Unlisted != "forward" && d.Unlisted != "refuse") || (d.Unlisted == "forward") != (d.Resolver != "") {
			return nil, errors.New("dns needs listen, and unlisted forward with a resolver or unlisted refuse")
		}
		if c.Transport.Transparent == nil {
			return nil, errors.New("dns steering requires a transparent transport")
		}
	}
	if c.Transport.SocketMode == "" {
		c.Transport.SocketMode = "0600"
	}
	c.Credentials.CredentialsDirectory = resolve(base, c.Credentials.CredentialsDirectory)
	for name, p := range c.Credentials.Providers {
		if (p.Script == "") == (p.ScriptFile == "") {
			return nil, errors.New("credential adapter requires exactly one of script or script_file")
		}
		if p.ScriptFile != "" {
			script, err := readFile(resolve(base, p.ScriptFile), MaxAdapterBytes)
			if err != nil {
				return nil, err
			}
			p.Script = string(script)
			p.ScriptFile = ""
			c.Credentials.Providers[name] = p
		}
	}
	for name, b := range c.Credentials.Bindings {
		b.StateFile = resolve(base, b.StateFile)
		for alias, source := range b.Secrets {
			source.File = resolve(base, source.File)
			b.Secrets[alias] = source
		}
		c.Credentials.Bindings[name] = b
	}
	l := &Loaded{Config: c, REST: make(map[string]*schema.RESTSchema), GraphQL: make(map[string]*schema.GraphQLSchema), Catalogs: make(map[string]schema.Catalog)}
	defer func() {
		if err != nil {
			l.Close()
		}
	}()
	if c.CAFile != "" {
		pem, err := readFile(resolve(base, c.CAFile), 1<<20)
		if err != nil {
			return nil, err
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("invalid CA certificate file")
		}
		l.RootCAs = roots
		c.Credentials.RootCAs = roots
	}
	for name, spec := range c.Schemas {
		if name == "" || spec.File == "" {
			return nil, errors.New("schema name and file are required")
		}
		data, err := readFile(resolve(base, spec.File), MaxSchemaBytes)
		if err != nil {
			return nil, err
		}
		switch spec.Protocol {
		case "rest":
			s, err := schema.CompileREST(data)
			if err != nil {
				return nil, errors.New("invalid REST schema")
			}
			l.REST[name] = s
			l.Catalogs[name] = s.Catalog()
		case "graphql":
			s, err := schema.CompileGraphQL(data)
			if err != nil {
				return nil, errors.New("invalid GraphQL schema")
			}
			l.GraphQL[name] = s
			l.Catalogs[name] = s.Catalog()
		default:
			return nil, errors.New("schema protocol must be rest or graphql")
		}
	}
	for i, u := range c.Upstreams {
		if u.Binding != "" {
			if len(u.Bindings) != 0 {
				return nil, errors.New("upstream takes binding or bindings, not both")
			}
			u.Bindings, u.Binding = []string{u.Binding}, ""
		}
		if u.TLS == "" {
			u.TLS = "intercept"
		}
		if u.TLS != "intercept" && u.TLS != "tunnel" {
			return nil, errors.New("upstream tls must be intercept or tunnel")
		}
		if u.Schema != "" {
			if _, ok := l.Catalogs[u.Schema]; !ok {
				return nil, errors.New("upstream references an unknown schema")
			}
		}
		c.Upstreams[i] = u
	}
	policyConfig, err := loadPolicy(base, c.Revision, c.Policy)
	if err != nil {
		return nil, err
	}
	l.Config = c
	l.Policy, err = policy.New(ctx, policyConfig)
	if err != nil {
		return nil, errors.New("invalid authorization policy")
	}
	l.Credentials, err = credential.New(c.Credentials)
	if err != nil {
		return nil, errors.New("invalid credential configuration")
	}
	return l, nil
}
