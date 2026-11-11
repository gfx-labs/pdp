package gateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gfx-labs/pdp/pkg/auth"
	"github.com/gfx-labs/pdp/pkg/credential"
	"github.com/gfx-labs/pdp/pkg/policy"
	"github.com/gfx-labs/pdp/pkg/schema"
)

// candidate picks the binding a request may receive. A placeholder only
// routes: policy still has to allow the binding for the verified caller.
func (u *upstream) candidate(h http.Header, body []byte) *binding {
	if u == nil || len(u.bindings) == 0 {
		return nil
	}
	if len(u.bindings) == 1 && len(u.tokenPaths) == 0 {
		return &u.bindings[0]
	}
	for i := range u.bindings {
		if carriesPlaceholder(h, body, u.bindings[i].Placeholder) {
			return &u.bindings[i]
		}
	}
	return nil
}

// request authorizes and forwards one HTTP request to dest.
func (x *exchange) request(identity auth.Identity, dest destination) {
	g, r := x.g, x.r
	up := x.s.upstreams[dest.key()]
	if up != nil && up.Tunnel {
		// A tunnel upstream is opaque by configuration. Reading it would need
		// the interception this entry turned off.
		x.fail(http.StatusBadRequest, "invalid_request")
		return
	}
	// A credential or a pinned schema is never used over plaintext HTTP.
	if up != nil && dest.scheme != "https" && (len(up.bindings) > 0 || up.strict()) {
		x.fail(http.StatusBadRequest, "invalid_request")
		return
	}
	input := policy.Input{Version: policy.InputVersion, Identity: policyIdentity(identity), Protocol: policy.ProtocolHTTP,
		Destination: policy.Destination{Scheme: dest.scheme, Host: dest.host, Port: dest.port}}
	limit := g.opts.StreamTimeout
	var body []byte
	var query url.Values
	if up.strict() {
		limit = g.opts.RequestTimeout
		if validateStrict(r, g.opts) != nil || (up.GraphQL != nil && r.URL.Path != up.GraphQLPath) {
			x.fail(http.StatusBadRequest, "invalid_request")
			return
		}
		normalized, canonical, parsed, err := normalize(r, up, g.opts.MaxRequestBytes)
		if err != nil {
			x.fail(http.StatusBadRequest, "invalid_request")
			return
		}
		body, query = canonical, parsed
		addSchemaFacts(&input, up, normalized, r.URL.Path, query)
	} else {
		parsed, err := url.ParseQuery(r.URL.RawQuery)
		if validateGeneric(r, g.opts) != nil || err != nil {
			x.fail(http.StatusBadRequest, "invalid_request")
			return
		}
		input.HTTP = &policy.HTTPInput{Method: r.Method, Path: r.URL.EscapedPath(), Query: parsed}
		if isWebSocket(r) {
			input.Protocol = policy.ProtocolWebSocket
		}
	}
	token := up != nil && up.tokenPaths[r.URL.Path]
	var tokenBody []byte
	if token {
		// The refresh body names the placeholder, so it is read to route.
		var err error
		tokenBody, err = io.ReadAll(io.LimitReader(r.Body, g.opts.MaxRequestBytes+1))
		if err != nil || int64(len(tokenBody)) > g.opts.MaxRequestBytes || input.Protocol != policy.ProtocolHTTP {
			x.fail(http.StatusBadRequest, "invalid_request")
			return
		}
	}
	chosen := up.candidate(r.Header, tokenBody)
	if chosen != nil {
		input.Binding = chosen.name
	}
	ctx, cancel := context.WithTimeout(r.Context(), limit)
	defer cancel()
	controller := http.NewResponseController(x.w)
	_ = controller.SetReadDeadline(x.started.Add(limit))
	_ = controller.SetWriteDeadline(x.started.Add(limit + time.Second))
	if token {
		x.answerToken(ctx, &input, chosen)
		return
	}
	addresses, ok := x.authorize(ctx, &input, true)
	if !ok {
		return
	}
	var lease credential.Result
	var leaseRequest credential.Request
	if chosen != nil {
		var err error
		leaseRequest = credential.Request{Provider: chosen.Provider, Binding: chosen.name, Scopes: up.Scopes}
		if lease, err = x.s.credentials.Get(ctx, leaseRequest); err != nil {
			x.fail(http.StatusBadGateway, "credential_unavailable")
			return
		}
	}
	target := &url.URL{Scheme: dest.scheme, Host: dest.authority(), Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery}
	var out *http.Request
	var err error
	if up.strict() {
		target.RawPath, target.RawQuery = "", query.Encode()
		if out, err = http.NewRequestWithContext(ctx, r.Method, target.String(), bytes.NewReader(body)); err == nil {
			// A fresh header set drops every caller header, including cookies
			// and whatever authentication the caller tried to supply.
			out.Header.Set("Accept", "application/json")
			out.Header.Set("Accept-Encoding", "identity")
			out.Header.Set("User-Agent", "pdp/1")
			if len(body) > 0 {
				out.Header.Set("Content-Type", "application/json")
			}
		}
	} else {
		var stream io.Reader = r.Body
		if r.ContentLength == 0 {
			stream = http.NoBody
		}
		if out, err = http.NewRequestWithContext(ctx, r.Method, target.String(), stream); err == nil {
			out.ContentLength = r.ContentLength
			out.Header = r.Header.Clone()
			removeHopHeaders(out.Header)
			if input.Protocol == policy.ProtocolWebSocket {
				out.Header.Set("Connection", "Upgrade")
				out.Header.Set("Upgrade", "websocket")
			}
		}
	}
	if err != nil {
		x.fail(http.StatusBadRequest, "invalid_request")
		return
	}
	// "Connection: close" beside "Connection: Upgrade" would refuse the upgrade.
	out.Close, out.GetBody = input.Protocol != policy.ProtocolWebSocket, nil
	if chosen != nil {
		// Every field that could carry the caller's own or placeholder
		// credential is replaced, not only the one the adapter sets.
		out.Header.Del("Authorization")
		out.Header.Del("Cookie")
		out.Header.Del(lease.HeaderName())
		if chosen.Placeholder != "" {
			for name, values := range out.Header {
				if carriesPlaceholder(http.Header{name: values}, nil, chosen.Placeholder) {
					out.Header.Del(name)
				}
			}
		}
		for name, value := range chosen.Headers {
			out.Header.Set(name, value)
		}
		// The response scan reads raw bytes, so no compressed response.
		out.Header.Set("Accept-Encoding", "identity")
		if err = lease.Apply(out.Header); err != nil {
			x.fail(http.StatusBadGateway, "credential_unavailable")
			return
		}
	}
	// No Client is used: RoundTrip performs exactly one request and cannot follow redirects.
	response, err := g.transport.RoundTrip(out.WithContext(context.WithValue(ctx, pinKey{}, addresses)))
	if err != nil {
		x.fail(http.StatusBadGateway, "upstream_unavailable")
		return
	}
	defer response.Body.Close()
	if chosen != nil && (response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden) {
		x.s.credentials.Invalidate(leaseRequest)
	}
	switch {
	case up.strict():
		x.respondBuffered(response, lease)
	case response.StatusCode == http.StatusSwitchingProtocols:
		x.respondUpgrade(response, input.Protocol == policy.ProtocolWebSocket, chosen != nil, lease)
	default:
		x.respondStream(response, chosen != nil, lease)
	}
}

// placeholderLifetime is the expiry reported for a placeholder. The client asks
// again after it, and the real credential's lifetime is the adapter's concern.
const placeholderLifetime = time.Hour

// answerToken replies to a token request with the placeholder, so a refresh
// never carries a real token to the workload. Nothing is sent upstream.
func (x *exchange) answerToken(ctx context.Context, input *policy.Input, chosen *binding) {
	if chosen == nil {
		x.event.Protocol, x.event.Host, x.event.Port = input.Protocol, auditLabel(input.Destination.Host), input.Destination.Port
		x.fail(http.StatusForbidden, "forbidden")
		return
	}
	if _, ok := x.authorize(ctx, input, false); !ok {
		return
	}
	data, _ := json.Marshal(map[string]any{
		"access_token": chosen.Placeholder, "refresh_token": chosen.Placeholder,
		"token_type": "Bearer", "expires_in": int(placeholderLifetime / time.Second),
	})
	x.w.Header().Set("Content-Type", "application/json")
	x.w.Header().Set("Cache-Control", "no-store")
	x.status, x.outcome = http.StatusOK, "token_answered"
	x.w.WriteHeader(x.status)
	_, _ = x.w.Write(data)
}

// respondBuffered returns a bounded JSON response from a schema-backed upstream.
func (x *exchange) respondBuffered(response *http.Response, lease credential.Result) {
	data, err := readResponse(response, x.g.opts)
	if err != nil || lease.ContainsSecret(data) {
		x.fail(http.StatusBadGateway, "invalid_upstream_response")
		return
	}
	// Go's transport removes Connection: close before exposing response headers,
	// so reconstruct locally rather than retain hidden connection-nominated fields.
	if len(data) > 0 {
		x.w.Header().Set("Content-Type", "application/json")
	}
	x.w.Header().Set("Cache-Control", "no-store")
	x.w.Header().Set("X-Content-Type-Options", "nosniff")
	x.status, x.outcome = response.StatusCode, "forwarded"
	x.event.BytesReceived = int64(len(data))
	x.w.WriteHeader(x.status)
	if x.r.Method != "HEAD" {
		_, _ = x.w.Write(data)
	}
}

func headersCarrySecret(h http.Header, lease credential.Result) bool {
	for _, values := range h {
		for _, v := range values {
			if lease.ContainsSecret([]byte(v)) {
				return true
			}
		}
	}
	return false
}

// respondStream relays a response as it arrives. With an injected credential
// the bytes are scanned on the way, and a match ends the connection.
func (x *exchange) respondStream(response *http.Response, credentialed bool, lease credential.Result) {
	removeHopHeaders(response.Header)
	if credentialed {
		encoding := response.Header.Get("Content-Encoding")
		if (encoding != "" && !strings.EqualFold(encoding, "identity")) || headersCarrySecret(response.Header, lease) {
			x.fail(http.StatusBadGateway, "invalid_upstream_response")
			return
		}
	}
	header := x.w.Header()
	for name, values := range response.Header {
		header[name] = values
	}
	x.status, x.outcome = response.StatusCode, "forwarded"
	x.w.WriteHeader(x.status)
	controller := http.NewResponseController(x.w)
	scanner := lease.Scanner()
	buffer := make([]byte, 32<<10)
	for {
		n, err := response.Body.Read(buffer)
		chunk := buffer[:n]
		if credentialed && n > 0 {
			var found bool
			if chunk, found = scanner.Next(chunk); found {
				// Headers are already sent, so the only signal left is to cut
				// the connection before the credential is written.
				x.status, x.outcome = http.StatusBadGateway, "credential_reflected"
				panic(http.ErrAbortHandler)
			}
		}
		if err != nil && credentialed {
			chunk = append(chunk, scanner.Flush()...)
		}
		if len(chunk) > 0 {
			if _, writeErr := x.w.Write(chunk); writeErr != nil {
				return
			}
			x.event.BytesReceived += int64(len(chunk))
			_ = controller.Flush()
		}
		if err != nil {
			if err != io.EOF {
				x.outcome = "upstream_interrupted"
				panic(http.ErrAbortHandler)
			}
			return
		}
	}
}

// respondUpgrade relays a WebSocket after the upstream accepted the upgrade.
// Frames are not inspected.
func (x *exchange) respondUpgrade(response *http.Response, requested, credentialed bool, lease credential.Result) {
	backend, ok := response.Body.(io.ReadWriteCloser)
	if !requested || !ok || (credentialed && headersCarrySecret(response.Header, lease)) {
		x.fail(http.StatusBadGateway, "invalid_upstream_response")
		return
	}
	conn, buffered, err := http.NewResponseController(x.w).Hijack()
	if err != nil {
		x.fail(http.StatusInternalServerError, "internal_error")
		return
	}
	x.hijacked = true
	defer conn.Close()
	response.Body = nil
	if err = response.Write(buffered); err == nil {
		err = buffered.Flush()
	}
	if err != nil {
		x.status, x.outcome = http.StatusBadGateway, "upstream_unavailable"
		return
	}
	x.status, x.outcome = http.StatusSwitchingProtocols, "upgraded"
	x.event.BytesSent, x.event.BytesReceived = relay(&bufferedConn{Conn: conn, reader: buffered.Reader}, backend, x.started.Add(x.g.opts.StreamTimeout))
}

// relay copies both ways until either side ends or the deadline passes.
func relay(client net.Conn, backend io.ReadWriteCloser, deadline time.Time) (sent, received int64) {
	_ = client.SetDeadline(deadline)
	if c, ok := backend.(net.Conn); ok {
		_ = c.SetDeadline(deadline)
	}
	timer := time.AfterFunc(time.Until(deadline), func() { client.Close(); backend.Close() })
	defer timer.Stop()
	done := make(chan struct{})
	go func() {
		received, _ = io.Copy(client, backend)
		client.Close()
		backend.Close()
		close(done)
	}()
	sent, _ = io.Copy(backend, client)
	client.Close()
	backend.Close()
	<-done
	return sent, received
}

// connect handles CONNECT host:port. A tunnel upstream is relayed unread after
// one policy decision. Anything else is intercepted, and each request inside
// is then authorized like any other.
func (x *exchange) connect(identity auth.Identity, outer *http.Request) (after func()) {
	g := x.g
	dest, ok := splitDestination("tcp", x.r.Host)
	if !ok || x.r.ProtoMajor != 1 {
		x.fail(http.StatusBadRequest, "invalid_request")
		return nil
	}
	x.event.Host, x.event.Port = auditLabel(dest.host), dest.port
	if up := x.s.upstreams[dest.key()]; up != nil && up.Tunnel {
		release, ok := x.admit()
		if !ok {
			return nil
		}
		defer release()
		input := policy.Input{Version: policy.InputVersion, Identity: policyIdentity(identity), Protocol: policy.ProtocolTunnel,
			Destination: policy.Destination{Scheme: "tcp", Host: dest.host, Port: dest.port}}
		ctx, cancel := context.WithTimeout(x.r.Context(), g.opts.RequestTimeout)
		defer cancel()
		addresses, ok := x.authorize(ctx, &input, true)
		if !ok {
			return nil
		}
		backend, err := g.dialPinned(context.WithValue(ctx, pinKey{}, addresses), "tcp", dest.key())
		if err != nil {
			x.fail(http.StatusBadGateway, "upstream_unavailable")
			return nil
		}
		client, ok := x.establish()
		if !ok {
			backend.Close()
			return nil
		}
		x.status, x.outcome = http.StatusOK, "tunneled"
		x.event.BytesSent, x.event.BytesReceived = relay(client, backend, time.Now().Add(g.opts.StreamTimeout))
		return nil
	}
	x.event.Protocol = policy.ProtocolHTTP
	if g.opts.Interception == nil {
		x.fail(http.StatusForbidden, "interception_unavailable")
		return nil
	}
	select {
	case g.conns <- struct{}{}:
	default:
		x.fail(http.StatusServiceUnavailable, "concurrency_limited")
		return nil
	}
	client, ok := x.establish()
	if !ok {
		<-g.conns
		return nil
	}
	x.status, x.outcome = http.StatusOK, "intercepting"
	// The inner requests run after this exchange releases its snapshot, so a
	// long-lived connection picks up reloads request by request.
	return func() {
		defer func() { <-g.conns }()
		g.intercepted(client, outer, dest)
	}
}

// establish takes over the client connection and confirms the CONNECT.
func (x *exchange) establish() (net.Conn, bool) {
	conn, buffered, err := http.NewResponseController(x.w).Hijack()
	if err != nil {
		x.fail(http.StatusInternalServerError, "internal_error")
		return nil, false
	}
	x.hijacked = true
	_ = conn.SetDeadline(time.Time{})
	if _, err = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err == nil {
		err = buffered.Flush()
	}
	if err != nil {
		conn.Close()
		x.status, x.outcome = http.StatusBadGateway, "client_closed"
		return nil, false
	}
	return &bufferedConn{Conn: conn, reader: buffered.Reader}, true
}

// intercepted serves the HTTP requests a client sends inside a CONNECT.
func (g *Gateway) intercepted(client net.Conn, outer *http.Request, dest destination) {
	defer client.Close()
	_ = client.SetReadDeadline(time.Now().Add(g.opts.RequestTimeout))
	reader := client.(*bufferedConn).reader
	first, err := reader.Peek(1)
	if err != nil {
		return
	}
	dest.scheme = "http"
	conn := client
	// 0x16 is a TLS handshake record. Anything else is read as plain HTTP.
	if first[0] == 0x16 {
		dest.scheme = "https"
		secured := tls.Server(client, &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"},
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				return g.opts.Interception.Certificate(dest.host)
			}})
		ctx, cancel := context.WithTimeout(context.Background(), g.opts.RequestTimeout)
		err = secured.HandshakeContext(ctx)
		cancel()
		if err != nil {
			return
		}
		conn = secured
	}
	_ = client.SetReadDeadline(time.Time{})
	listener := &oneConnListener{conn: conn, done: make(chan struct{})}
	var handlers sync.WaitGroup
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlers.Add(1)
			defer handlers.Done()
			g.serve(w, r, outer, &dest)
		}),
		ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: g.opts.MaxHeaderBytes, ErrorLog: log.New(io.Discard, "", 0),
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed || state == http.StateHijacked {
				listener.Close()
			}
		},
	}
	_ = server.Serve(listener)
	// A handler that hijacked the connection for a WebSocket still owns it.
	handlers.Wait()
}

// bufferedConn reads bytes the HTTP server had already buffered before a hijack.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

// oneConnListener hands one established connection to an http.Server.
type oneConnListener struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
	mu   sync.Mutex
	used bool
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	first := !l.used
	l.used = true
	l.mu.Unlock()
	if first {
		return l.conn, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *oneConnListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

func readResponse(r *http.Response, o Options) ([]byte, error) {
	if r.StatusCode < 200 || r.StatusCode >= 600 || r.StatusCode >= 300 && r.StatusCode < 400 || r.StatusCode == 101 || len(r.Trailer) != 0 || r.Header.Get("Trailer") != "" || r.Header.Get("Upgrade") != "" || r.Header.Get("Content-Encoding") != "" {
		return nil, errRequest
	}
	if len(r.Header.Values("Content-Type")) > 1 {
		return nil, errRequest
	}
	if typ := r.Header.Get("Content-Type"); typ != "" {
		media, params, err := mime.ParseMediaType(typ)
		if err != nil || media != "application/json" || len(params) > 1 {
			return nil, errRequest
		}
		for k, v := range params {
			if k != "charset" || !strings.EqualFold(v, "utf-8") {
				return nil, errRequest
			}
		}
	}
	if r.ContentLength > o.MaxResponseBytes {
		return nil, errRequest
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, o.MaxResponseBytes+1))
	if err != nil || int64(len(data)) > o.MaxResponseBytes || len(r.Trailer) != 0 {
		return nil, errRequest
	}
	if len(data) > 0 {
		if _, err := schema.DecodeJSON(data); err != nil {
			return nil, errRequest
		}
	}
	return data, nil
}
