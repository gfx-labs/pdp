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

	"github.com/gfx-labs/pdp/internal/credential"
	"github.com/gfx-labs/pdp/internal/policy"
	"github.com/gfx-labs/pdp/internal/schema"
	"go.yaml.in/yaml/v3"
)

const Version = "pdp.config/v1"
const MaxConfigBytes = 4 << 20
const MaxSchemaBytes = 4 << 20

// Relative paths are resolved against the configuration file, never cwd.
type Config struct {
	Version        string            `json:"version"`
	Revision       string            `json:"revision"`
	CAFile         string            `json:"ca_file,omitempty"`
	Limits         Limits            `json:"limits,omitempty"`
	Transport      Transport         `json:"transport"`
	Identities     map[uint32]string `json:"identities"`
	PrincipalTasks map[string]string `json:"principal_tasks,omitempty"`
	Schemas        map[string]Schema `json:"schemas,omitempty"`
	Routes         []Route           `json:"routes"`
	Credentials    credential.Config `json:"credentials"`
	Policy         policy.Config     `json:"policy"`
}

type Limits struct {
	MaxRequestBytes  int64         `json:"max_request_bytes,omitempty"`
	MaxResponseBytes int64         `json:"max_response_bytes,omitempty"`
	MaxHeaderBytes   int           `json:"max_header_bytes,omitempty"`
	MaxConcurrent    int           `json:"max_concurrent,omitempty"`
	RequestTimeout   time.Duration `json:"request_timeout,omitempty"`
}

type Transport struct {
	UnixSocket string  `json:"unix_socket"`
	SocketMode string  `json:"socket_mode,omitempty"`
	SPIFFE     *SPIFFE `json:"spiffe,omitempty"`
}

type SPIFFE struct {
	Address     string            `json:"address"`
	WorkloadAPI string            `json:"workload_api"`
	Principals  map[string]string `json:"principals"`
}

type Schema struct {
	Protocol string `json:"protocol"`
	File     string `json:"file"`
}

type Route struct {
	Provider    string   `json:"provider"`
	Binding     string   `json:"binding"`
	UpstreamURL string   `json:"upstream_url,omitempty"`
	Schema      string   `json:"schema,omitempty"`
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

// decode uses JSON tags as the single public naming convention for JSON and
// YAML. YAML duplicate keys, multiple documents and JSON unknown fields fail.
func decode(data []byte, target any) error {
	var raw any
	if json.Valid(data) {
		var err error
		raw, err = schema.DecodeJSON(data)
		if err != nil {
			return errors.New("invalid configuration JSON")
		}
	} else {
		dec := yaml.NewDecoder(bytes.NewReader(data))
		var node yaml.Node
		if err := dec.Decode(&node); err != nil {
			return errors.New("invalid configuration syntax")
		}
		var extra yaml.Node
		if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
			return errors.New("configuration must contain exactly one document")
		}
		var err error
		raw, err = yamlValue(&node, 0)
		if err != nil {
			return err
		}
	}
	if root, ok := raw.(map[string]any); ok {
		for _, path := range [][]string{{"limits", "request_timeout"}, {"credentials", "limits", "timeout"}, {"credentials", "limits", "expiry_margin"}, {"policy", "relationships", "max_age"}} {
			if err := normalizeDuration(root, path); err != nil {
				return err
			}
		}
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return errors.New("configuration keys must be strings")
	}
	jd := json.NewDecoder(bytes.NewReader(b))
	jd.DisallowUnknownFields()
	jd.UseNumber()
	if err := jd.Decode(target); err != nil {
		return errors.New("invalid configuration field or value")
	}
	return nil
}

// Numeric lexemes pass through JSON's exact-number parser, never float64.
// YAML aliases, merges and non-string keys have no configuration semantics.
func yamlValue(node *yaml.Node, depth int) (any, error) {
	if depth > 64 {
		return nil, errors.New("configuration nesting exceeds limit")
	}
	switch node.Kind {
	case yaml.DocumentNode:
		if len(node.Content) != 1 {
			return nil, errors.New("empty configuration")
		}
		return yamlValue(node.Content[0], depth)
	case yaml.MappingNode:
		out := map[string]any{}
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				return nil, errors.New("configuration keys must be strings, quote numeric UIDs")
			}
			if _, exists := out[key.Value]; exists {
				return nil, errors.New("duplicate configuration key")
			}
			value, err := yamlValue(node.Content[i+1], depth+1)
			if err != nil {
				return nil, err
			}
			out[key.Value] = value
		}
		return out, nil
	case yaml.SequenceNode:
		out := make([]any, 0, len(node.Content))
		for _, child := range node.Content {
			value, err := yamlValue(child, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, value)
		}
		return out, nil
	case yaml.ScalarNode:
		switch node.Tag {
		case "!!str", "!!timestamp":
			return node.Value, nil
		case "!!null":
			if node.Value == "" || node.Value == "~" || strings.EqualFold(node.Value, "null") {
				return nil, nil
			}
		case "!!bool":
			if strings.EqualFold(node.Value, "true") {
				return true, nil
			}
			if strings.EqualFold(node.Value, "false") {
				return false, nil
			}
		case "!!int", "!!float":
			value, err := schema.DecodeJSON([]byte(node.Value))
			if err == nil {
				if number, ok := value.(json.Number); ok {
					return number, nil
				}
			}
			return nil, errors.New("configuration numbers must use finite JSON numeric notation")
		}
	}
	return nil, errors.New("unsupported YAML alias, merge or tag")
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
	if value, ok := root[key].(string); ok {
		d, err := time.ParseDuration(value)
		if err != nil {
			return errors.New("invalid configuration duration")
		}
		root[key] = int64(d)
	}
	return nil
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
	if c.Transport.SocketMode == "" {
		c.Transport.SocketMode = "0600"
	}
	c.Credentials.CredentialsDirectory = resolve(base, c.Credentials.CredentialsDirectory)
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
	for _, r := range c.Routes {
		if r.Schema != "" {
			if _, ok := l.Catalogs[r.Schema]; !ok {
				return nil, errors.New("route references an unknown schema")
			}
		}
	}
	addProfiles(&c, l.Catalogs)
	if err = validateReferences(&c, l.Catalogs); err != nil {
		return nil, err
	}
	c.Policy.Revision = c.Revision
	l.Config = c
	l.Policy, err = policy.New(ctx, c.Policy)
	if err != nil {
		return nil, errors.New("invalid authorization policy")
	}
	for _, d := range l.Policy.Diagnostics() {
		if d.Code == "unknown_operation_reference" {
			return nil, errors.New("policy references an unknown operation")
		}
	}
	l.Credentials, err = credential.New(c.Credentials)
	if err != nil {
		return nil, errors.New("invalid credential configuration")
	}
	return l, nil
}
