package credential

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"go.starlark.net/starlark"
	"go.starlark.net/syntax"
)

type flight struct {
	done    chan struct{}
	result  Result
	err     error
	invalid bool
}
type Manager struct {
	cfg       Config
	programs  map[string]*starlark.Program
	client    *http.Client
	transport *http.Transport
	sem       chan struct{}
	mu        sync.Mutex
	cache     map[string]Result
	calls     map[string]*flight
	poisoned  map[string]bool
	stats     Stats
	closed    bool
	ctx       context.Context
	cancel    context.CancelFunc
}

func (*Manager) String() string                  { return "credential.Manager([redacted])" }
func (m *Manager) GoString() string              { return m.String() }
func (m *Manager) Format(s fmt.State, verb rune) { _, _ = s.Write([]byte(m.String())) }

// Stats uses the existing cache mutex, adding no atomic operation to cache hits.
// AcquisitionNanoseconds includes script, lock, disk and network time until
// completion, but excludes joined waiters and input validation.
func (m *Manager) Stats() Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	snapshot := m.stats
	snapshot.InFlight = uint64(len(m.calls))
	return snapshot
}

// New validates and compiles configuration without fetching any secret or token.
// The caller must replace the entire Manager on configuration reload.
func New(cfg Config) (*Manager, error) {
	cfg = cloneConfig(cfg)
	l := &cfg.Limits
	if l.MaxSteps == 0 {
		l.MaxSteps = 100000
	}
	if l.Timeout == 0 {
		l.Timeout = 10 * time.Second
	}
	if l.MaxConcurrent == 0 {
		l.MaxConcurrent = 8
	}
	if l.MaxInputBytes == 0 {
		l.MaxInputBytes = 8192
	}
	if l.MaxOutputBytes == 0 {
		l.MaxOutputBytes = 16384
	}
	if l.MaxScriptBytes == 0 {
		l.MaxScriptBytes = 65536
	}
	if l.MaxHTTPResponseBytes == 0 {
		l.MaxHTTPResponseBytes = 262144
	}
	if l.CacheEntries == 0 {
		l.CacheEntries = 1024
	}
	if l.ExpiryMargin == 0 {
		l.ExpiryMargin = 30 * time.Second
	}
	if l.MaxSteps > 10000000 || l.Timeout < time.Millisecond || l.Timeout > time.Minute || l.MaxConcurrent < 1 || l.MaxConcurrent > 128 || l.MaxInputBytes < 1 || l.MaxInputBytes > 1048576 || l.MaxOutputBytes < 1 || l.MaxOutputBytes > 1048576 || l.MaxScriptBytes < 1 || l.MaxScriptBytes > 1048576 || l.MaxHTTPResponseBytes < 1 || l.MaxHTTPResponseBytes > 1048576 || l.CacheEntries < 1 || l.CacheEntries > 100000 || l.ExpiryMargin < 0 || l.ExpiryMargin > 24*time.Hour {
		return nil, failure(CodeInvalid)
	}
	if cfg.CredentialsDirectory == "" {
		cfg.CredentialsDirectory = os.Getenv("CREDENTIALS_DIRECTORY")
	}
	if cfg.CredentialsDirectory != "" && !filepath.IsAbs(cfg.CredentialsDirectory) {
		return nil, failure(CodeInvalid)
	}
	m := &Manager{cfg: cfg, programs: make(map[string]*starlark.Program), sem: make(chan struct{}, l.MaxConcurrent), cache: make(map[string]Result), calls: make(map[string]*flight), poisoned: make(map[string]bool)}
	for name, p := range cfg.Providers {
		if !validValue(name, 256) || p.ScriptFile != "" || len(p.Script) == 0 || len(p.Script) > l.MaxScriptBytes {
			return nil, failure(CodeInvalid)
		}
		for alias, endpoint := range p.Endpoints {
			u, err := url.Parse(endpoint)
			if !validValue(alias, 256) || err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.Opaque != "" || !validValue(endpoint, 4096) {
				return nil, failure(CodeInvalid)
			}
		}
		ast, prog, err := starlark.SourceProgramOptions(&syntax.FileOptions{}, "credential.star", p.Script, func(n string) bool { return builtinNames[n] })
		if err != nil || prog.NumLoads() != 0 {
			return nil, failure(CodeInvalid)
		}
		found := false
		for _, stmt := range ast.Stmts {
			if d, ok := stmt.(*syntax.DefStmt); ok && d.Name.Name == "acquire" && len(d.Params) == 1 {
				found = true
			}
		}
		if !found {
			return nil, failure(CodeInvalid)
		}
		m.programs[name] = prog
	}
	states := map[string]bool{}
	for name, b := range cfg.Bindings {
		_, ok := m.programs[b.Provider]
		raw, _ := json.Marshal(b)
		if !validValue(name, 256) || !ok || len(raw) > l.MaxInputBytes {
			return nil, failure(CodeInvalid)
		}
		if _, err := canonicalScopes(b.Scopes); err != nil {
			return nil, err
		}
		for alias, s := range b.Secrets {
			if !validValue(alias, 256) || (s.File == "") == (s.SystemdCredential == "") {
				return nil, failure(CodeInvalid)
			}
			if s.File != "" && !filepath.IsAbs(s.File) {
				return nil, failure(CodeInvalid)
			}
			if s.SystemdCredential != "" && (cfg.CredentialsDirectory == "" || filepath.Base(s.SystemdCredential) != s.SystemdCredential || s.SystemdCredential == "." || s.SystemdCredential == "..") {
				return nil, failure(CodeInvalid)
			}
		}
		if b.StateFile != "" {
			if !filepath.IsAbs(b.StateFile) || states[filepath.Clean(b.StateFile)] {
				return nil, failure(CodeInvalid)
			}
			states[filepath.Clean(b.StateFile)] = true
		}
		if b.LinearActor != "" && b.LinearActor != "app" && b.LinearActor != "user" {
			return nil, failure(CodeInvalid)
		}
		if g := b.GitHub; g != nil {
			if !validValue(g.AppID, 256) || len(g.RepositoryIDs) == 0 || len(g.RepositoryIDs) > 500 || len(g.Permissions) == 0 {
				return nil, failure(CodeInvalid)
			}
			seen := map[int64]bool{}
			for _, id := range g.RepositoryIDs {
				if id <= 0 || seen[id] {
					return nil, failure(CodeInvalid)
				}
				seen[id] = true
			}
			for permission, level := range g.Permissions {
				if !validValue(permission, 128) || (level != "read" && level != "write") {
					return nil, failure(CodeInvalid)
				}
			}
		}
	}
	roots := cfg.RootCAs
	if roots != nil {
		roots = roots.Clone()
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	// A rotating grant is not replay-safe, including transport-level retries.
	// Fresh HTTP/1 connections avoid reused-connection and HTTP/2 retry paths.
	m.transport = &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: l.Timeout}).DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, NextProtos: []string{"http/1.1"}},
		Protocols:              protocols,
		DisableKeepAlives:      true,
		TLSHandshakeTimeout:    l.Timeout,
		ResponseHeaderTimeout:  l.Timeout,
		MaxResponseHeaderBytes: int64(l.MaxHTTPResponseBytes),
		MaxConnsPerHost:        l.MaxConcurrent,
		DisableCompression:     true,
	}
	m.client = &http.Client{Transport: m.transport, Timeout: l.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	m.ctx, m.cancel = context.WithCancel(context.Background())
	return m, nil
}

func cloneConfig(c Config) Config {
	p := make(map[string]ProviderConfig, len(c.Providers))
	for k, v := range c.Providers {
		v.Endpoints = cloneMap(v.Endpoints)
		p[k] = v
	}
	c.Providers = p
	b := make(map[string]BindingConfig, len(c.Bindings))
	for k, v := range c.Bindings {
		secrets := make(map[string]SecretSource, len(v.Secrets))
		for n, s := range v.Secrets {
			secrets[n] = s
		}
		v.Secrets = secrets
		v.Parameters = cloneMap(v.Parameters)
		v.Scopes = append([]string(nil), v.Scopes...)
		if v.GitHub != nil {
			g := *v.GitHub
			g.RepositoryIDs = append([]int64(nil), g.RepositoryIDs...)
			g.Permissions = cloneMap(g.Permissions)
			v.GitHub = &g
		}
		b[k] = v
	}
	c.Bindings = b
	return c
}
func cloneMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
func canonicalScopes(in []string) ([]string, error) {
	if len(in) > 128 {
		return nil, failure(CodeInvalid)
	}
	out := append([]string(nil), in...)
	sort.Strings(out)
	for i, s := range out {
		if !validValue(s, 256) || strings.ContainsAny(s, " ,\t\n") || (i > 0 && out[i-1] == s) {
			return nil, failure(CodeInvalid)
		}
	}
	return out, nil
}
func (m *Manager) request(r Request) (Request, string, error) {
	b, ok := m.cfg.Bindings[r.Binding]
	if !ok || r.Provider != b.Provider {
		return r, "", failure(CodeInvalid)
	}
	scopes, err := canonicalScopes(r.Scopes)
	if err != nil {
		return r, "", err
	}
	r.Scopes = scopes
	allowed := map[string]bool{}
	for _, s := range b.Scopes {
		allowed[s] = true
	}
	for _, s := range scopes {
		if !allowed[s] {
			return r, "", failure(CodeInvalid)
		}
	}
	raw, _ := json.Marshal(r)
	if len(raw) > m.cfg.Limits.MaxInputBytes {
		return r, "", failure(CodeLimited)
	}
	return r, string(raw), nil
}

// Validate checks an administrator-selected binding and scope set without I/O.
func (m *Manager) Validate(r Request) error {
	_, _, err := m.request(r)
	return err
}

// Get coalesces acquisitions by provider, binding and canonical scope set.
// Expiring credentials are removed before acquisition. Failures never serve stale data.
func (m *Manager) Get(ctx context.Context, r Request) (Result, error) {
	if ctx == nil {
		return Result{}, failure(CodeInvalid)
	}
	r, key, err := m.request(r)
	if err != nil {
		return Result{}, err
	}
	if ctx.Err() != nil {
		return Result{}, failure(CodeCanceled)
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return Result{}, failure(CodeUnavailable)
	}
	if cached, ok := m.cache[key]; ok {
		if time.Now().Add(m.cfg.Limits.ExpiryMargin).Before(cached.ExpiresAt) {
			m.stats.Hits++
			m.mu.Unlock()
			return cached, nil
		}
		delete(m.cache, key)
	}
	m.stats.Misses++
	if call, ok := m.calls[key]; ok {
		m.stats.Coalesced++
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			return Result{}, failure(CodeCanceled)
		case <-call.done:
			return call.result, call.err
		}
	}
	select {
	case m.sem <- struct{}{}:
	default:
		m.mu.Unlock()
		return Result{}, failure(CodeLimited)
	}
	call := &flight{done: make(chan struct{})}
	m.calls[key] = call
	m.stats.Acquisitions++
	m.mu.Unlock()
	started := time.Now()
	acquisition, cancel := context.WithTimeout(ctx, m.cfg.Limits.Timeout)
	stop := context.AfterFunc(m.ctx, cancel)
	result, err := m.execute(acquisition, r)
	stop()
	cancel()
	m.mu.Lock()
	if call.invalid || m.closed {
		result = Result{}
		err = failure(CodeUnavailable)
	}
	m.stats.AcquisitionNanoseconds += uint64(time.Since(started).Nanoseconds())
	if err != nil {
		m.stats.Failures++
	}
	if err == nil {
		if len(m.cache) >= m.cfg.Limits.CacheEntries {
			for k := range m.cache {
				delete(m.cache, k)
				break
			}
		}
		m.cache[key] = result
	}
	call.result = result
	call.err = err
	delete(m.calls, key)
	<-m.sem
	close(call.done)
	m.mu.Unlock()
	return result, err
}

// Invalidate discards an exact scope lease and prevents an in-flight lease from
// becoming visible. Call on upstream authentication failure, without blind retry.
func (m *Manager) Invalidate(r Request) {
	_, key, err := m.request(r)
	if err != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.cache, key)
	if c := m.calls[key]; c != nil {
		c.invalid = true
	}
}
func (m *Manager) Close() {
	m.mu.Lock()
	if !m.closed {
		m.closed = true
		m.cancel()
		clear(m.cache)
		for _, c := range m.calls {
			c.invalid = true
		}
	}
	m.mu.Unlock()
	m.transport.CloseIdleConnections()
}
