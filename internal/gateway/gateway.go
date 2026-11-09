// Package gateway implements the authenticated, schema-bounded upstream gateway.
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
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gfx-labs/pdp/internal/auth"
	"github.com/gfx-labs/pdp/internal/credential"
	"github.com/gfx-labs/pdp/internal/policy"
	"github.com/gfx-labs/pdp/internal/schema"
)

type Route struct {
	Provider    string
	Binding     string
	UpstreamURL string
	Scopes      []string
	REST        *schema.RESTSchema
	GraphQL     *schema.GraphQLSchema
}

type SnapshotConfig struct {
	Version        string
	Authenticator  auth.Authenticator
	PrincipalTasks map[string]string
	Routes         []Route
	Policy         *policy.Engine
	Credentials    *credential.Manager
	OnRetire       func()
}

type route struct {
	Route
	upstream *url.URL
}

// Snapshot holds one immutable routing, identity, schema, policy and adapter view.
// Its dependencies must not be closed while a request using it remains in flight.
type Snapshot struct {
	version        string
	authenticator  auth.Authenticator
	principalTasks map[string]string
	routes         map[string]route
	policy         *policy.Engine
	credentials    *credential.Manager
	mu             sync.Mutex
	refs           int
	retired        bool
	done           chan struct{}
	onRetire       func()
	cleanup        sync.Once
}

func NewSnapshot(c SnapshotConfig) (*Snapshot, error) {
	if !safeLabel(c.Version) || c.Authenticator == nil || c.Policy == nil || c.Credentials == nil || len(c.Routes) == 0 || len(c.Routes) > 2 {
		return nil, errors.New("invalid gateway snapshot")
	}
	s := &Snapshot{version: c.Version, authenticator: c.Authenticator, policy: c.Policy, credentials: c.Credentials, routes: make(map[string]route), done: make(chan struct{}), onRetire: c.OnRetire}
	s.principalTasks = make(map[string]string, len(c.PrincipalTasks))
	for principal, task := range c.PrincipalTasks {
		if !safeLabel(principal) || !safeLabel(task) {
			return nil, errors.New("invalid principal task mapping")
		}
		s.principalTasks[principal] = task
	}
	for _, r := range c.Routes {
		if !safeLabel(r.Binding) {
			return nil, errors.New("invalid route binding")
		}
		if _, ok := s.routes[r.Provider]; ok {
			return nil, errors.New("duplicate provider route")
		}
		switch r.Provider {
		case "github":
			if r.GraphQL != nil {
				return nil, errors.New("GitHub route cannot use GraphQL schema")
			}
			if r.UpstreamURL == "" {
				r.UpstreamURL = "https://api.github.com"
			}
		case "linear":
			if r.REST != nil {
				return nil, errors.New("Linear route cannot use REST schema")
			}
			if r.UpstreamURL == "" {
				r.UpstreamURL = "https://api.linear.app/graphql"
			}
		default:
			return nil, errors.New("unsupported provider route")
		}
		u, err := url.Parse(r.UpstreamURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.Opaque != "" || strings.ContainsAny(r.UpstreamURL, "\\\r\n\t") {
			return nil, errors.New("upstream must be a fixed HTTPS endpoint")
		}
		if r.Provider == "github" && u.Path != "" && u.Path != "/" {
			return nil, errors.New("GitHub upstream must be an origin")
		}
		if r.Provider == "linear" && u.Path != "/graphql" {
			return nil, errors.New("Linear upstream must use /graphql")
		}
		r.Scopes = append([]string(nil), r.Scopes...)
		if err := c.Credentials.Validate(credential.Request{Provider: r.Provider, Binding: r.Binding, Scopes: r.Scopes}); err != nil {
			return nil, errors.New("invalid route credential binding")
		}
		s.routes[r.Provider] = route{Route: r, upstream: u}
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
	MaxRequestBytes  int64
	MaxResponseBytes int64
	MaxHeaderBytes   int
	MaxConcurrent    int
	RequestTimeout   time.Duration
	// RootCAs supplies explicit trust for private HTTPS upstreams. Nil uses system roots.
	RootCAs *x509.CertPool
	// Audit receives identifiers and fixed outcome codes only, never request values.
	Audit func(AuditEvent)
}

type AuditEvent struct {
	Time                 time.Time `json:"time"`
	Snapshot             string    `json:"snapshot"`
	Principal            string    `json:"principal,omitempty"`
	Provider             string    `json:"provider,omitempty"`
	Operation            string    `json:"operation,omitempty"`
	PolicyRevision       string    `json:"policy_revision,omitempty"`
	SchemaDigest         string    `json:"schema_digest,omitempty"`
	RelationshipRevision string    `json:"relationship_revision,omitempty"`
	MatchedGrants        []string  `json:"matched_grants,omitempty"`
	Operations           []string  `json:"operations,omitempty"`
	Outcome              string    `json:"outcome"`
	Status               int       `json:"status"`
	DurationMS           int64     `json:"duration_ms"`
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
	transport *http.Transport
	requests  atomic.Uint64
	allowed   atomic.Uint64
	denied    atomic.Uint64
	failed    atomic.Uint64
	inflight  atomic.Int64
}

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
	if o.MaxRequestBytes < 1 || o.MaxRequestBytes > schema.MaxBodyBytes || o.MaxResponseBytes < 1 || o.MaxResponseBytes > schema.MaxDocumentBytes || o.MaxHeaderBytes < 1024 || o.MaxHeaderBytes > 64<<10 || o.MaxConcurrent < 1 || o.MaxConcurrent > 1024 || o.RequestTimeout < time.Millisecond || o.RequestTimeout > time.Minute {
		return nil, errors.New("invalid gateway limits")
	}
	roots := o.RootCAs
	if roots != nil {
		roots = roots.Clone()
	}
	g := &Gateway{opts: o, sem: make(chan struct{}, o.MaxConcurrent)}
	// A fresh HTTP/1 connection per request prevents Transport's reused-connection retries.
	g.transport = &http.Transport{
		Proxy: nil, DialContext: (&net.Dialer{Timeout: o.RequestTimeout}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, NextProtos: []string{"http/1.1"}},
		TLSNextProto:        map[string]func(string, *tls.Conn) http.RoundTripper{},
		TLSHandshakeTimeout: o.RequestTimeout, ResponseHeaderTimeout: o.RequestTimeout,
		MaxResponseHeaderBytes: int64(o.MaxHeaderBytes), DisableCompression: true,
		DisableKeepAlives: true, MaxConnsPerHost: o.MaxConcurrent, ForceAttemptHTTP2: false,
	}
	g.current.Store(s)
	return g, nil
}

// Reload publishes one complete view. In-flight requests retain their old view.
// Revocation applies when a request loads the pointer, not midway through a write.
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

func NewHTTPServer(addr string, g *Gateway) *http.Server {
	connections := make(chan struct{}, 2*g.opts.MaxConcurrent)
	var accepted sync.Map
	return &http.Server{Addr: addr, Handler: g, ConnContext: auth.ConnContext,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: g.opts.RequestTimeout,
		WriteTimeout: g.opts.RequestTimeout + time.Second, IdleTimeout: 30 * time.Second,
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

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	var s *Snapshot
	for {
		s = g.current.Load()
		if s == nil {
			writeError(w, http.StatusServiceUnavailable, "gateway_closed")
			return
		}
		if s.acquire() {
			break
		}
	}
	defer s.release()
	event := AuditEvent{Time: started.UTC(), Snapshot: s.version, PolicyRevision: auditLabel(s.policy.Revision())}
	status := http.StatusInternalServerError
	outcome := "internal_error"
	g.requests.Add(1)
	defer func() {
		event.Status = status
		event.Outcome = outcome
		event.DurationMS = time.Since(started).Milliseconds()
		if status >= 500 {
			g.failed.Add(1)
		} else if outcome != "forwarded" {
			g.denied.Add(1)
		}
		if g.opts.Audit != nil {
			g.opts.Audit(event)
		}
	}()
	fail := func(code int, reason string) { status = code; outcome = reason; writeError(w, code, reason) }
	identity, err := s.authenticator.Authenticate(r)
	if err != nil || !safeLabel(identity.Principal) {
		fail(http.StatusUnauthorized, "unauthenticated")
		return
	}
	event.Principal = identity.Principal
	provider, path, ok := selectRoute(r.URL.Path)
	if !ok {
		fail(http.StatusNotFound, "route_not_found")
		return
	}
	route, ok := s.routes[provider]
	if !ok {
		fail(http.StatusNotFound, "route_not_found")
		return
	}
	event.Provider = provider
	select {
	case g.sem <- struct{}{}:
	default:
		fail(http.StatusServiceUnavailable, "concurrency_limited")
		return
	}
	g.inflight.Add(1)
	defer func() { <-g.sem; g.inflight.Add(-1) }()
	ctx, cancel := context.WithTimeout(r.Context(), g.opts.RequestTimeout)
	defer cancel()
	deadline := started.Add(g.opts.RequestTimeout)
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(deadline)
	_ = controller.SetWriteDeadline(deadline.Add(time.Second))
	if err := validateRequest(r, g.opts); err != nil {
		fail(http.StatusBadRequest, "invalid_request")
		return
	}
	normalized, body, query, err := normalize(r.WithContext(ctx), path, route, g.opts.MaxRequestBytes)
	if err != nil {
		fail(http.StatusBadRequest, "invalid_request")
		return
	}
	input := policyInput(identity, route, normalized, path, query)
	input.Identity.TaskID = s.principalTasks[identity.Principal]
	event.SchemaDigest = input.SchemaDigest
	for _, op := range input.Operations {
		if safeLabel(op.ID) {
			event.Operations = append(event.Operations, op.ID)
		}
	}
	if len(input.Operations) == 1 && safeLabel(input.Operations[0].ID) {
		event.Operation = input.Operations[0].ID
	}
	decision, err := s.policy.Evaluate(ctx, input)
	event.RelationshipRevision = auditLabel(decision.RelationshipRevision)
	for _, grant := range decision.MatchedGrants {
		if safeLabel(grant) {
			event.MatchedGrants = append(event.MatchedGrants, grant)
		}
	}
	if err != nil || !decision.Allow {
		fail(http.StatusForbidden, "forbidden")
		return
	}
	leaseRequest := credential.Request{Provider: provider, Binding: route.Binding, Scopes: route.Scopes}
	lease, err := s.credentials.Get(ctx, leaseRequest)
	if err != nil {
		fail(http.StatusBadGateway, "credential_unavailable")
		return
	}
	target := *route.upstream
	if provider == "github" {
		target.Path = path
		target.RawPath = ""
		target.RawQuery = query.Encode()
	}
	upstream, err := newUpstreamRequest(ctx, r, &target, body, provider)
	if err != nil {
		fail(http.StatusBadRequest, "invalid_request")
		return
	}
	if err = lease.Apply(upstream.Header); err != nil {
		fail(http.StatusBadGateway, "credential_unavailable")
		return
	}
	// No Client is used: RoundTrip performs exactly one request and cannot follow redirects.
	response, err := g.transport.RoundTrip(upstream)
	if err != nil {
		fail(http.StatusBadGateway, "upstream_unavailable")
		return
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		s.credentials.Invalidate(leaseRequest)
	}
	data, err := readResponse(response, g.opts)
	if err != nil {
		fail(http.StatusBadGateway, "invalid_upstream_response")
		return
	}
	if lease.ContainsSecret(data) {
		fail(http.StatusBadGateway, "invalid_upstream_response")
		return
	}
	// Go's transport removes Connection: close before exposing response headers,
	// so reconstruct locally rather than retain hidden connection-nominated fields.
	if len(data) > 0 {
		w.Header().Set("Content-Type", "application/json")
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	status = response.StatusCode
	outcome = "forwarded"
	g.allowed.Add(1)
	w.WriteHeader(status)
	if r.Method != "HEAD" {
		_, _ = w.Write(data)
	}
}
