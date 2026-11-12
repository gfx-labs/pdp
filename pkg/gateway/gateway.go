// Package gateway implements the authenticated forward proxy: it identifies the
// caller, asks policy about the destination, then injects a credential.
package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gfx-labs/pdp/pkg/auth"
	"github.com/gfx-labs/pdp/pkg/credential"
	"github.com/gfx-labs/pdp/pkg/intercept"
	"github.com/gfx-labs/pdp/pkg/policy"
	"github.com/gfx-labs/pdp/pkg/schema"
)

// Upstream attaches a credential, schema or TLS mode to one destination. It is
// not an allowlist: a destination with no entry still goes to policy.
type Upstream struct {
	Host string
	Port int // 0 means 443
	// Tunnel relays CONNECT bytes without terminating TLS. Policy then sees
	// only host and port, and no credential can be injected.
	Tunnel bool
	// Bindings are the credentials this destination may receive. With several,
	// the caller's placeholder selects the candidate that policy must allow.
	Bindings []string
	Scopes   []string
	// Plugin names the pinned schema in policy input and audit records.
	Plugin  string
	REST    *schema.RESTSchema
	GraphQL *schema.GraphQLSchema
	// GraphQLPath is the only path a GraphQL upstream accepts. Default /graphql.
	GraphQLPath string
	// TokenPaths are token endpoints answered locally with the placeholder, so
	// a refresh never returns a real token to the workload.
	TokenPaths []string
}

type SnapshotConfig struct {
	Version       string
	Authenticator auth.Authenticator
	Upstreams     []Upstream
	Policy        *policy.Engine
	Credentials   *credential.Manager
	OnRetire      func()
}

type binding struct {
	name string
	credential.Binding
}

type upstream struct {
	Upstream
	digest     string
	bindings   []binding
	tokenPaths map[string]bool
}

func (u *upstream) strict() bool { return u != nil && (u.REST != nil || u.GraphQL != nil) }

// Snapshot holds one immutable upstream, identity, schema, policy and adapter view.
// Its dependencies must not be closed while a request using it remains in flight.
type Snapshot struct {
	version       string
	authenticator auth.Authenticator
	upstreams     map[string]*upstream
	policy        *policy.Engine
	credentials   *credential.Manager
	mu            sync.Mutex
	refs          int
	retired       bool
	done          chan struct{}
	onRetire      func()
	cleanup       sync.Once
}

func NewSnapshot(c SnapshotConfig) (*Snapshot, error) {
	if !safeLabel(c.Version) || c.Authenticator == nil || c.Policy == nil || c.Credentials == nil || len(c.Upstreams) > 1024 {
		return nil, errors.New("invalid gateway snapshot")
	}
	s := &Snapshot{version: c.Version, authenticator: c.Authenticator, policy: c.Policy, credentials: c.Credentials, upstreams: make(map[string]*upstream), done: make(chan struct{}), onRetire: c.OnRetire}
	for _, u := range c.Upstreams {
		if u.Port == 0 {
			u.Port = 443
		}
		host, ok := normalizeHost(u.Host)
		if !ok || host != u.Host || u.Port < 1 || u.Port > 65535 {
			return nil, errors.New("upstream host must be a lower-case name or address with a valid port")
		}
		entry := &upstream{Upstream: u, tokenPaths: make(map[string]bool)}
		key := destination{host: u.Host, port: u.Port}.key()
		if _, exists := s.upstreams[key]; exists {
			return nil, errors.New("duplicate upstream")
		}
		if u.REST != nil && u.GraphQL != nil {
			return nil, errors.New("upstream cannot pin both a REST and a GraphQL schema")
		}
		if u.Tunnel && (len(u.Bindings) != 0 || entry.strict() || len(u.TokenPaths) != 0) {
			return nil, errors.New("a tunnel upstream cannot have a binding, schema or token path")
		}
		if entry.strict() {
			if !safeLabel(u.Plugin) {
				return nil, errors.New("a schema-backed upstream needs a plugin name")
			}
			if u.REST != nil {
				entry.digest = u.REST.Digest()
			} else {
				entry.digest = u.GraphQL.Digest()
				if entry.GraphQLPath == "" {
					entry.GraphQLPath = "/graphql"
				}
				if !validPath(entry.GraphQLPath) {
					return nil, errors.New("invalid GraphQL path")
				}
			}
		} else if u.Plugin != "" || u.GraphQLPath != "" {
			return nil, errors.New("plugin and GraphQL path require a schema")
		}
		entry.Scopes = append([]string(nil), u.Scopes...)
		placeholders := map[string]bool{}
		for _, name := range u.Bindings {
			b, ok := c.Credentials.Binding(name)
			if !ok || !safeLabel(name) || c.Credentials.Validate(credential.Request{Provider: b.Provider, Binding: name, Scopes: entry.Scopes}) != nil {
				return nil, errors.New("invalid upstream credential binding")
			}
			// Without distinct placeholders nothing could tell the accounts apart.
			if (len(u.Bindings) > 1 || len(u.TokenPaths) > 0) && (b.Placeholder == "" || placeholders[b.Placeholder]) {
				return nil, errors.New("each binding of this upstream needs its own placeholder")
			}
			placeholders[b.Placeholder] = true
			entry.bindings = append(entry.bindings, binding{name: name, Binding: b})
		}
		if len(u.TokenPaths) > 0 && (len(u.Bindings) == 0 || entry.strict()) {
			return nil, errors.New("token paths require a binding and no schema")
		}
		for _, path := range u.TokenPaths {
			if !validPath(path) {
				return nil, errors.New("invalid token path")
			}
			entry.tokenPaths[path] = true
		}
		s.upstreams[key] = entry
	}
	return s, nil
}

func (s *Snapshot) Version() string { return s.version }

func (s *Snapshot) acquire() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.retired {
		return false
	}
	s.refs++
	return true
}
func (s *Snapshot) release() {
	s.mu.Lock()
	s.refs--
	clean := s.retired && s.refs == 0
	s.mu.Unlock()
	if clean {
		s.dispose()
	}
}
func (s *Snapshot) retire() {
	s.mu.Lock()
	s.retired = true
	clean := s.refs == 0
	s.mu.Unlock()
	if clean {
		s.dispose()
	}
}
func (s *Snapshot) dispose() {
	s.cleanup.Do(func() {
		s.credentials.Close()
		if s.onRetire != nil {
			s.onRetire()
		}
		close(s.done)
	})
}
func (s *Snapshot) WaitDrained(ctx context.Context) error {
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type Options struct {
	// MaxRequestBytes and MaxResponseBytes bound schema-backed exchanges, which
	// are buffered. Other exchanges are relayed and bounded by StreamTimeout.
	MaxRequestBytes  int64
	MaxResponseBytes int64
	MaxHeaderBytes   int
	MaxConcurrent    int
	// RequestTimeout bounds a schema-backed exchange and the wait for any
	// upstream's response headers.
	RequestTimeout time.Duration
	// StreamTimeout bounds a relayed response, WebSocket or tunnel.
	StreamTimeout time.Duration
	// DisableUpstreamReuse opens a new upstream connection for every request.
	// With reuse, a request may travel on a connection dialed for an earlier
	// request to the same host and port, to the address resolved back then.
	DisableUpstreamReuse bool
	// RootCAs supplies explicit trust for private HTTPS upstreams. Nil uses system roots.
	RootCAs *x509.CertPool
	// Interception signs leaf certificates for CONNECT and transparent TLS.
	// Without it only tunnel upstreams and absolute-form requests are served.
	Interception *intercept.Authority
	// Lookup resolves a destination host. Nil uses the system resolver.
	Lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	// DialContext connects to one resolved address. Nil uses a plain TCP dialer.
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
	// Audit receives identifiers and fixed outcome codes only, never request values.
	Audit func(AuditEvent)
}

type AuditEvent struct {
	Time           time.Time `json:"time"`
	Snapshot       string    `json:"snapshot"`
	Principal      string    `json:"principal,omitempty"`
	Protocol       string    `json:"protocol,omitempty"`
	Host           string    `json:"host,omitempty"`
	Port           int       `json:"port,omitempty"`
	Binding        string    `json:"binding,omitempty"`
	Plugin         string    `json:"plugin,omitempty"`
	Operation      string    `json:"operation,omitempty"`
	PolicyRevision string    `json:"policy_revision,omitempty"`
	SchemaDigest   string    `json:"schema_digest,omitempty"`
	MatchedRules   []string  `json:"matched_rules,omitempty"`
	Operations     []string  `json:"operations,omitempty"`
	Outcome        string    `json:"outcome"`
	Status         int       `json:"status"`
	BytesSent      int64     `json:"bytes_sent,omitempty"`
	BytesReceived  int64     `json:"bytes_received,omitempty"`
	DurationMS     int64     `json:"duration_ms"`
}

type Metrics struct {
	Requests    uint64           `json:"requests"`
	Allowed     uint64           `json:"allowed"`
	Denied      uint64           `json:"denied"`
	Failed      uint64           `json:"failed"`
	InFlight    int64            `json:"in_flight"`
	Credentials credential.Stats `json:"credentials"`
}

type Gateway struct {
	current   atomic.Pointer[Snapshot]
	reloadMu  sync.Mutex
	closed    bool
	opts      Options
	sem       chan struct{}
	conns     chan struct{}
	transport *http.Transport
	roots     *x509.CertPool
	requests  atomic.Uint64
	allowed   atomic.Uint64
	denied    atomic.Uint64
	failed    atomic.Uint64
	inflight  atomic.Int64
}

type pinKey struct{}

func New(s *Snapshot, o Options) (*Gateway, error) {
	if s == nil {
		return nil, errors.New("gateway snapshot is required")
	}
	if o.MaxRequestBytes == 0 {
		o.MaxRequestBytes = 1 << 20
	}
	if o.MaxResponseBytes == 0 {
		o.MaxResponseBytes = 4 << 20
	}
	if o.MaxHeaderBytes == 0 {
		o.MaxHeaderBytes = 16 << 10
	}
	if o.MaxConcurrent == 0 {
		o.MaxConcurrent = 32
	}
	if o.RequestTimeout == 0 {
		o.RequestTimeout = 15 * time.Second
	}
	if o.StreamTimeout == 0 {
		o.StreamTimeout = 10 * time.Minute
	}
	if o.MaxRequestBytes < 1 || o.MaxRequestBytes > schema.MaxBodyBytes || o.MaxResponseBytes < 1 || o.MaxResponseBytes > schema.MaxDocumentBytes || o.MaxHeaderBytes < 1024 || o.MaxHeaderBytes > 64<<10 || o.MaxConcurrent < 1 || o.MaxConcurrent > 1024 || o.RequestTimeout < time.Millisecond || o.RequestTimeout > time.Minute || o.StreamTimeout < o.RequestTimeout || o.StreamTimeout > 24*time.Hour {
		return nil, errors.New("invalid gateway limits")
	}
	if o.Lookup == nil {
		o.Lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	if o.DialContext == nil {
		o.DialContext = (&net.Dialer{Timeout: o.RequestTimeout}).DialContext
	}
	g := &Gateway{opts: o, sem: make(chan struct{}, o.MaxConcurrent), conns: make(chan struct{}, 2*o.MaxConcurrent)}
	if o.RootCAs != nil {
		g.roots = o.RootCAs.Clone()
	}
	// Reused connections let Transport resend a request the upstream may not have
	// seen. It does that only for bodiless GET, HEAD, OPTIONS and TRACE, because
	// request sets GetBody to nil. HTTP/2 stays off.
	g.transport = &http.Transport{
		Proxy: nil, DialContext: g.dialPinned,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: g.roots, NextProtos: []string{"http/1.1"}},
		TLSNextProto:        map[string]func(string, *tls.Conn) http.RoundTripper{},
		TLSHandshakeTimeout: o.RequestTimeout, ResponseHeaderTimeout: o.RequestTimeout,
		MaxResponseHeaderBytes: int64(o.MaxHeaderBytes), DisableCompression: true,
		DisableKeepAlives: o.DisableUpstreamReuse, MaxConnsPerHost: o.MaxConcurrent, ForceAttemptHTTP2: false,
		MaxIdleConns: 2 * o.MaxConcurrent, MaxIdleConnsPerHost: o.MaxConcurrent, IdleConnTimeout: 30 * time.Second,
	}
	g.current.Store(s)
	return g, nil
}

// dialPinned connects only to the addresses policy was shown. A second DNS
// answer cannot move an allowed request to another host.
func (g *Gateway) dialPinned(ctx context.Context, network, address string) (net.Conn, error) {
	addresses, ok := ctx.Value(pinKey{}).([]netip.Addr)
	_, port, err := net.SplitHostPort(address)
	if !ok || len(addresses) == 0 || err != nil {
		return nil, errors.New("destination is not pinned")
	}
	for _, candidate := range addresses {
		var conn net.Conn
		if conn, err = g.opts.DialContext(ctx, "tcp", net.JoinHostPort(candidate.String(), port)); err == nil {
			return conn, nil
		}
	}
	return nil, err
}

func (g *Gateway) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	found, err := g.opts.Lookup(ctx, host)
	if err != nil || len(found) == 0 {
		return nil, errors.New("destination did not resolve")
	}
	if len(found) > 16 {
		found = found[:16]
	}
	out := make([]netip.Addr, len(found))
	for i, a := range found {
		out[i] = a.Unmap()
	}
	return out, nil
}

// Reload publishes one complete view. In-flight requests retain their old view.
// Revocation applies when a request loads the pointer, not midway through a write.
// A relayed stream or tunnel keeps its old view until it ends or StreamTimeout.
func (g *Gateway) Reload(s *Snapshot) error {
	if s == nil {
		return errors.New("gateway snapshot is required")
	}
	g.reloadMu.Lock()
	defer g.reloadMu.Unlock()
	if g.closed {
		return errors.New("gateway is closed")
	}
	s.mu.Lock()
	retired := s.retired
	s.mu.Unlock()
	if retired {
		return errors.New("snapshot is retired")
	}
	old := g.current.Swap(s)
	if old != s {
		old.retire()
	}
	// Connections the old snapshot's policy approved are not kept for the new one.
	g.transport.CloseIdleConnections()
	return nil
}
func (g *Gateway) Metrics() Metrics {
	metrics := Metrics{Requests: g.requests.Load(), Allowed: g.allowed.Load(), Denied: g.denied.Load(), Failed: g.failed.Load(), InFlight: g.inflight.Load()}
	if snapshot := g.current.Load(); snapshot != nil {
		metrics.Credentials = snapshot.credentials.Stats()
	}
	return metrics
}
func (g *Gateway) Close() {
	g.reloadMu.Lock()
	defer g.reloadMu.Unlock()
	if !g.closed {
		g.closed = true
		g.current.Swap(nil).retire()
	}
	g.transport.CloseIdleConnections()
}

func (g *Gateway) newServer(addr string, connContext func(context.Context, net.Conn) context.Context) *http.Server {
	connections := make(chan struct{}, 2*g.opts.MaxConcurrent)
	var accepted sync.Map
	// Read and write deadlines are set per request, because a relayed stream
	// outlives the bound that applies to a buffered exchange.
	return &http.Server{Addr: addr, Handler: g, ConnContext: connContext,
		ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: g.opts.MaxHeaderBytes, ErrorLog: log.New(io.Discard, "", 0),
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ConnState: func(c net.Conn, state http.ConnState) {
			switch state {
			case http.StateNew:
				select {
				case connections <- struct{}{}:
					accepted.Store(c, struct{}{})
				default:
					c.Close()
				}
			case http.StateClosed, http.StateHijacked:
				if _, ok := accepted.LoadAndDelete(c); ok {
					<-connections
				}
			}
		},
	}
}

// NewHTTPServer serves callers that address the proxy explicitly, over the
// Unix socket or the SPIFFE listener.
func NewHTTPServer(addr string, g *Gateway) *http.Server { return g.newServer(addr, auth.ConnContext) }

// NewTransparentServer serves DNS-steered callers, whose only identity is
// their source address.
func NewTransparentServer(addr string, g *Gateway) *http.Server {
	return g.newServer(addr, auth.TransparentConnContext)
}

// TransparentTLSConfig terminates TLS for whatever name a steered client asked
// for. Policy still decides whether the request to that name goes anywhere.
func (g *Gateway) TransparentTLSConfig() (*tls.Config, error) {
	if g.opts.Interception == nil {
		return nil, errors.New("transparent TLS requires an interception CA")
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		host, ok := normalizeHost(hello.ServerName)
		if !ok {
			return nil, errors.New("server name is required")
		}
		return g.opts.Interception.Certificate(host)
	}}, nil
}

func safeLabel(s string) bool {
	if len(s) == 0 || len(s) > 256 {
		return false
	}
	for _, c := range s {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

func auditLabel(s string) string {
	if safeLabel(s) {
		return s
	}
	return ""
}

// Outcomes that mean the caller got what it asked for.
var served = map[string]bool{"forwarded": true, "upgraded": true, "tunneled": true, "intercepting": true, "token_answered": true}

// exchange is the state of one request while it is authorized and relayed.
type exchange struct {
	g        *Gateway
	s        *Snapshot
	w        http.ResponseWriter
	r        *http.Request
	started  time.Time
	event    AuditEvent
	status   int
	outcome  string
	hijacked bool
}

func (x *exchange) fail(code int, reason string) {
	x.status, x.outcome = code, reason
	if !x.hijacked {
		writeError(x.w, code, reason)
	}
}

func (x *exchange) finish() {
	x.event.Status, x.event.Outcome = x.status, x.outcome
	x.event.DurationMS = time.Since(x.started).Milliseconds()
	switch {
	case x.status >= 500:
		x.g.failed.Add(1)
	case served[x.outcome]:
		x.g.allowed.Add(1)
	default:
		x.g.denied.Add(1)
	}
	if x.g.opts.Audit != nil {
		x.g.opts.Audit(x.event)
	}
}

// admit takes a concurrency slot. The returned release must be called.
func (x *exchange) admit() (release func(), ok bool) {
	select {
	case x.g.sem <- struct{}{}:
	default:
		x.fail(http.StatusServiceUnavailable, "concurrency_limited")
		return nil, false
	}
	x.g.inflight.Add(1)
	return func() { <-x.g.sem; x.g.inflight.Add(-1) }, true
}

// authorize asks policy about the destination, resolves it, then asks again
// with the addresses that will be dialed. A denied name is never looked up, so
// a caller cannot use lookups of refused names to send data out through DNS.
// With resolve false nothing will be dialed, so one decision is enough.
func (x *exchange) authorize(ctx context.Context, input *policy.Input, resolve bool) ([]netip.Addr, bool) {
	x.event.Protocol, x.event.Host, x.event.Port = input.Protocol, auditLabel(input.Destination.Host), input.Destination.Port
	x.event.Binding, x.event.Plugin, x.event.SchemaDigest = auditLabel(input.Binding), auditLabel(input.Plugin), input.SchemaDigest
	for _, op := range input.Operations {
		if safeLabel(op.ID) {
			x.event.Operations = append(x.event.Operations, op.ID)
		}
	}
	if len(x.event.Operations) == 1 && len(input.Operations) == 1 {
		x.event.Operation = x.event.Operations[0]
	}
	decide := func() bool {
		decision, err := x.s.policy.Evaluate(ctx, *input)
		x.event.MatchedRules = nil
		for _, rule := range decision.MatchedRules {
			if safeLabel(rule) {
				x.event.MatchedRules = append(x.event.MatchedRules, rule)
			}
		}
		if err != nil || !decision.Allow {
			x.fail(http.StatusForbidden, "forbidden")
			return false
		}
		return true
	}
	var addresses []netip.Addr
	if !resolve {
		return nil, decide()
	}
	if literal, err := netip.ParseAddr(input.Destination.Host); err == nil {
		addresses = []netip.Addr{literal}
	} else {
		if !decide() {
			return nil, false
		}
		if addresses, err = x.g.lookup(ctx, input.Destination.Host); err != nil {
			x.fail(http.StatusBadGateway, "destination_unresolved")
			return nil, false
		}
	}
	for _, address := range addresses {
		input.Destination.Addresses = append(input.Destination.Addresses, address.String())
	}
	if !decide() {
		return nil, false
	}
	return addresses, true
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) { g.serve(w, r, r, nil) }

// serve handles one request. outer is the request that carries the verified
// connection. fixed is set for a request read inside an intercepted CONNECT.
func (g *Gateway) serve(w http.ResponseWriter, r, outer *http.Request, fixed *destination) {
	if after := g.exchange(w, r, outer, fixed); after != nil {
		after()
	}
}

func (g *Gateway) exchange(w http.ResponseWriter, r, outer *http.Request, fixed *destination) (after func()) {
	started := time.Now()
	var s *Snapshot
	for {
		s = g.current.Load()
		if s == nil {
			writeError(w, http.StatusServiceUnavailable, "gateway_closed")
			return nil
		}
		if s.acquire() {
			break
		}
	}
	defer s.release()
	x := &exchange{g: g, s: s, w: w, r: r, started: started, status: http.StatusInternalServerError, outcome: "internal_error"}
	x.event = AuditEvent{Time: started.UTC(), Snapshot: s.version, PolicyRevision: auditLabel(s.policy.Revision())}
	g.requests.Add(1)
	defer x.finish()
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(started.Add(g.opts.RequestTimeout))
	_ = controller.SetWriteDeadline(started.Add(g.opts.RequestTimeout + time.Second))
	// The connection is authenticated again for every request, so a revoked
	// SPIFFE bundle also stops requests inside an already open CONNECT.
	identity, err := s.authenticator.Authenticate(outer)
	if err != nil || !safeLabel(identity.ID()) {
		x.fail(http.StatusUnauthorized, "unauthenticated")
		return nil
	}
	x.event.Principal = identity.ID()
	if r.URL.Path == "" && r.Method != http.MethodConnect {
		r.URL.Path = "/"
	}
	if r.Method == http.MethodConnect {
		if fixed != nil {
			x.fail(http.StatusBadRequest, "invalid_request")
			return nil
		}
		return x.connect(identity, outer)
	}
	dest, ok := requestDestination(r)
	if fixed != nil {
		// Inside a CONNECT the destination is the tunnel's, whatever Host says.
		named, namedOK := splitDestination(fixed.scheme, r.Host)
		if r.URL.IsAbs() {
			namedOK = ok && dest == named
		}
		dest, ok = *fixed, namedOK && named == *fixed
	}
	if !ok {
		x.fail(http.StatusBadRequest, "invalid_request")
		return nil
	}
	release, ok := x.admit()
	if !ok {
		return nil
	}
	defer release()
	x.request(identity, dest)
	return nil
}
