package gateway

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gfx-labs/pdp/pkg/auth"
	"github.com/gfx-labs/pdp/pkg/credential"
	"github.com/gfx-labs/pdp/pkg/policy"
	"github.com/gfx-labs/pdp/pkg/schema"
)

const testToken = "pdp-test-provider-secret-7b35ef91"

type harness struct {
	g        *Gateway
	snapshot *Snapshot
	client   *http.Client
	socket   string
	roots    *x509.CertPool
	endpoint string
	eventsMu sync.Mutex
	events   []AuditEvent
}

func policyFor(t *testing.T, version string, allow bool) *policy.Engine {
	t.Helper()
	module := "package pdp.authz\nimport rego.v1\ndefault allow := false\n"
	uid := os.Getuid()
	if !allow {
		uid++
	}
	module += fmt.Sprintf("allow if { input.identity.auth_method == \"unix\"; input.identity.uid == %d; input.provider in {\"github\", \"linear\"}; input.binding == \"installation\" }\nmatched_rules contains \"authenticated-peer\" if allow\n", uid)
	return engineFor(t, version, module, nil)
}

func engineFor(t *testing.T, version, module string, data map[string]any) *policy.Engine {
	t.Helper()
	path := filepath.Join(t.TempDir(), "authz.rego")
	if err := os.WriteFile(path, []byte(module), 0600); err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := policy.New(context.Background(), policy.Config{Revision: version, Modules: map[string]string{"authz.rego": string(source)}, Data: data})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func managerFor(t *testing.T, token string) *credential.Manager {
	return managerForProvider(t, token, "github")
}

func managerForProvider(t *testing.T, token, provider string) *credential.Manager {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	manager, err := credential.New(credential.Config{
		Providers: map[string]credential.ProviderConfig{provider: {Script: "def acquire(ctx):\n    return static(secret(\"token\"))\n"}},
		Bindings:  map[string]credential.BindingConfig{"installation": {Provider: provider, Secrets: map[string]credential.SecretSource{"token": {File: path}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func newHarness(t *testing.T, handler http.HandlerFunc, allow bool, options Options) *harness {
	t.Helper()
	upstream := httptest.NewTLSServer(handler)
	t.Cleanup(upstream.Close)
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	if options.RootCAs == nil {
		options.RootCAs = roots
	}
	h := &harness{roots: roots, endpoint: upstream.URL}
	options.Audit = func(event AuditEvent) { h.eventsMu.Lock(); h.events = append(h.events, event); h.eventsMu.Unlock() }
	authenticator := auth.NewUnix()
	snapshot, err := NewSnapshot(SnapshotConfig{Version: "v1", Authenticator: authenticator, Policy: policyFor(t, "p1", allow), Credentials: managerFor(t, testToken), Routes: []Route{{Provider: "github", Binding: "installation", UpstreamURL: upstream.URL}}})
	if err != nil {
		t.Fatal(err)
	}
	h.snapshot = snapshot
	h.g, err = New(snapshot, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.g.Close)
	socketDir := t.TempDir()
	if err = os.Chmod(socketDir, 0700); err != nil {
		t.Fatal(err)
	}
	h.socket = filepath.Join(socketDir, "p.sock")
	listener, err := auth.ListenUnix(h.socket, 0600)
	if err != nil {
		t.Fatal(err)
	}
	server := NewHTTPServer("", h.g)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Close()
		if err := <-done; err != http.ErrServerClosed {
			t.Error(err)
		}
	})
	transport := &http.Transport{DisableCompression: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", h.socket)
	}}
	h.client = &http.Client{Transport: transport, Timeout: 3 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	return h
}

func (h *harness) request(t *testing.T, method, path, body string, headers http.Header) (int, http.Header, string) {
	t.Helper()
	r, err := http.NewRequest(method, "http://pdp"+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header = headers
	if body != "" && r.Header.Get("Content-Type") == "" {
		r.Header.Set("Content-Type", "application/json")
	}
	response, err := h.client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, response.Header, string(data)
}

// These tests use kernel-authenticated Unix clients, the real policy/adapter
// pipeline and verified TLS endpoints. They protect the gateway boundary itself.
func TestUnixTLSForward(t *testing.T) {
	var calls atomic.Int64
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.TLS == nil || r.URL.Path != "/repos/team/project/issues" || r.Host == "evil.invalid" {
			t.Error("destination was not fixed")
		}
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			t.Error("credential injection failed")
		}
		for _, name := range []string{"Cookie", "X-Principal", "X-API-Key", "Proxy-Authorization", "X-Forwarded-For", "X-Custom-Hop"} {
			if r.Header.Get(name) != "" {
				t.Errorf("caller header forwarded: %s", name)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", testToken)
		w.Header().Set("WWW-Authenticate", testToken)
		w.Header().Set("X-Debug", testToken)
		w.Header().Set("Location", "https://evil.invalid/"+testToken)
		w.Header().Set("Connection", "X-Ratelimit-Remaining")
		w.Header().Set("X-RateLimit-Remaining", "7")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}, true, Options{})
	headers := http.Header{"Authorization": {"Bearer caller"}, "Cookie": {"caller-secret"}, "X-Principal": {"root"}, "X-Api-Key": {"caller-key"}, "Proxy-Authorization": {"caller-proxy"}, "X-Forwarded-For": {"untrusted"}, "Connection": {"X-Custom-Hop"}, "X-Custom-Hop": {"untrusted"}}
	status, response, body := h.request(t, "GET", "/upstreams/github/repos/team/project/issues", "", headers)
	if status != 200 || body != `{"ok":true}` || calls.Load() != 1 {
		t.Fatalf("status=%d body=%s calls=%d", status, body, calls.Load())
	}
	for name, values := range response {
		if strings.Contains(strings.Join(values, ""), testToken) {
			t.Errorf("response leaked via %s", name)
		}
	}
	if response.Get("Set-Cookie") != "" || response.Get("Location") != "" || response.Get("WWW-Authenticate") != "" {
		t.Fatal("sensitive response headers forwarded")
	}
	if response.Get("X-RateLimit-Remaining") != "" {
		t.Fatal("connection-nominated response header forwarded")
	}
	h.eventsMu.Lock()
	audit, _ := json.Marshal(h.events)
	h.eventsMu.Unlock()
	if strings.Contains(string(audit), testToken) || strings.Contains(string(audit), "caller-secret") || strings.Contains(string(audit), "/repos/") {
		t.Fatalf("audit contains request values: %s", audit)
	}
	metrics := h.g.Metrics()
	if metrics.Requests != 1 || metrics.Allowed != 1 || metrics.Failed != 0 {
		t.Fatalf("metrics: %+v", metrics)
	}
}

func TestDeniedNeverForwards(t *testing.T) {
	var calls atomic.Int64
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}, false, Options{})
	status, _, body := h.request(t, "GET", "/upstreams/github/repos/team/project", "", http.Header{"Authorization": {"Bearer trusted"}, "X-Principal": {"alice"}, "X-Uid": {fmt.Sprint(os.Getuid() + 1)}, "X-Spiffe-Id": {"spiffe://example.test/admin"}})
	if status != 403 || calls.Load() != 0 || strings.Contains(body, testToken) {
		t.Fatalf("denied request crossed boundary: status=%d calls=%d body=%s", status, calls.Load(), body)
	}
	// A TCP request cannot acquire Unix identity from headers or a remote address.
	tcp := httptest.NewServer(h.g)
	defer tcp.Close()
	response, err := http.Get(tcp.URL + "/upstreams/github/repos/team/project")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 401 || calls.Load() != 0 {
		t.Fatalf("non-Unix caller accepted: %d", response.StatusCode)
	}
	stats := h.g.Metrics().Credentials
	if stats.Hits != 0 || stats.Misses != 0 || stats.Acquisitions != 0 {
		t.Fatalf("denied peer accessed credentials: %+v", stats)
	}
}

func TestAmbiguitiesNeverForward(t *testing.T) {
	var calls atomic.Int64
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}, true, Options{MaxRequestBytes: 128})
	cases := []struct {
		name, method, path, body string
		headers                  http.Header
	}{
		{"encoded slash", "GET", "/upstreams/github/repos/a%2Fb", "", nil},
		{"double slash", "GET", "/upstreams/github/repos//a", "", nil},
		{"dot segment", "GET", "/upstreams/github/repos/../a", "", nil},
		{"duplicate query", "GET", "/upstreams/github/repos/a?x=1&%78=2", "", nil},
		{"empty query part", "GET", "/upstreams/github/repos/a?x=1&&y=2", "", nil},
		{"missing query equals", "GET", "/upstreams/github/repos/a?x", "", nil},
		{"JSON duplicate", "POST", "/upstreams/github/repos/a", `{"a":1,"a":2}`, nil},
		{"JSON trailing", "POST", "/upstreams/github/repos/a", `{} {}`, nil},
		{"body array", "POST", "/upstreams/github/repos/a", `[{},{}]`, nil},
		{"encoding", "POST", "/upstreams/github/repos/a", `{}`, http.Header{"Content-Encoding": {"gzip"}}},
		{"upgrade", "GET", "/upstreams/github/repos/a", "", http.Header{"Connection": {"upgrade"}, "Upgrade": {"websocket"}}},
		{"body limit", "POST", "/upstreams/github/repos/a", `{"a":"` + strings.Repeat("x", 130) + `"}`, nil},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			headers := test.headers
			if headers == nil {
				headers = http.Header{}
			}
			status, _, _ := h.request(t, test.method, test.path, test.body, headers)
			if status != 400 {
				t.Fatalf("status %d", status)
			}
		})
	}
	// Exercise HTTP wire framing directly rather than relying on client rewriting.
	for _, raw := range []string{
		"POST /upstreams/github/a HTTP/1.1\r\nHost: pdp\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
		"POST /upstreams/github/a HTTP/1.1\r\nHost: pdp\r\nContent-Type: application/json\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
	} {
		conn, err := net.Dial("unix", h.socket)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, err = io.WriteString(conn, raw)
		if err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		conn.Close()
		if response.StatusCode != 400 {
			t.Fatalf("wire ambiguity status=%d", response.StatusCode)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid request reached upstream %d times", calls.Load())
	}
}

func TestResponseBoundary(t *testing.T) {
	var targetCalls atomic.Int64
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}))
	defer redirect.Close()
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/redirect":
			w.Header().Set("Location", redirect.URL)
			w.WriteHeader(302)
		case "/large":
			_, _ = io.WriteString(w, strings.Repeat("x", 257))
		case "/stream":
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: secret\n")
		case "/compressed":
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = io.WriteString(w, "not gzip")
		case "/error":
			w.WriteHeader(400)
			_, _ = fmt.Fprintf(w, `{"error":%q}`, r.Header.Get("Authorization"))
		case "/safe-error":
			w.WriteHeader(400)
			_, _ = io.WriteString(w, `{"errors":[{"message":"invalid field"}]}`)
		case "/reflect":
			_, _ = fmt.Fprintf(w, `{"debug":%q}`, r.Header.Get("Authorization"))
		case "/escaped", "/escaped-error":
			if r.URL.Path == "/escaped-error" {
				w.WriteHeader(400)
			}
			_, _ = io.WriteString(w, `{"debug":"`+strings.ReplaceAll(testToken, "p", `\u0070`)+`"}`)
		case "/malformed", "/malformed-error":
			if r.URL.Path == "/malformed-error" {
				w.WriteHeader(400)
			}
			_, _ = io.WriteString(w, `not-json {"debug":"`+strings.ReplaceAll(testToken, "p", `\u0070`)+`"}`)
		}
	}, true, Options{MaxResponseBytes: 256})
	for _, path := range []string{"redirect", "large", "stream", "compressed", "reflect", "escaped", "malformed", "error", "escaped-error", "malformed-error"} {
		t.Run(path, func(t *testing.T) {
			status, headers, body := h.request(t, "GET", "/upstreams/github/"+path, "", http.Header{})
			if status != 502 || strings.Contains(body, testToken) || headers.Get("Location") != "" {
				t.Fatalf("status=%d body=%s", status, body)
			}
		})
	}
	status, _, body := h.request(t, "GET", "/upstreams/github/safe-error", "", http.Header{})
	if status != 400 || body != `{"errors":[{"message":"invalid field"}]}` {
		t.Fatalf("safe provider error changed: %d %s", status, body)
	}
	if targetCalls.Load() != 0 {
		t.Fatal("redirect followed")
	}
}

func TestAtomicReload(t *testing.T) {
	started := make(chan struct{})
	finish := make(chan struct{})
	var calls atomic.Int64
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == "/hold" {
			close(started)
			<-finish
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"done":true}`)
	}, true, Options{})
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	onExistingConnection := func() int {
		t.Helper()
		if _, err := io.WriteString(conn, "GET /upstreams/github/warm HTTP/1.1\r\nHost: pdp\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if _, err = io.Copy(io.Discard, response.Body); err != nil {
			t.Fatal(err)
		}
		return response.StatusCode
	}
	if status := onExistingConnection(); status != 200 {
		t.Fatalf("initial peer authorization: %d", status)
	}
	result := make(chan int, 1)
	go func() {
		r, err := h.client.Get("http://pdp/upstreams/github/hold")
		if err != nil {
			result <- 0
			return
		}
		defer r.Body.Close()
		io.Copy(io.Discard, r.Body)
		result <- r.StatusCode
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not start")
	}
	authenticator := auth.NewUnix()
	next, err := NewSnapshot(SnapshotConfig{Version: "v2", Authenticator: authenticator, Policy: policyFor(t, "p2", false), Credentials: managerFor(t, "rotated-provider-token"), Routes: []Route{{Provider: "github", Binding: "installation", UpstreamURL: h.endpoint}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = h.g.Reload(next); err != nil {
		t.Fatal(err)
	}
	select {
	case <-h.snapshot.done:
		t.Fatal("old snapshot disposed while request in flight")
	default:
	}
	status := onExistingConnection()
	if status != 403 || calls.Load() != 2 {
		t.Fatalf("revoked identity reached upstream status=%d calls=%d", status, calls.Load())
	}
	if stats := h.g.Metrics().Credentials; stats.Hits != 0 || stats.Misses != 0 || stats.Acquisitions != 0 {
		t.Fatalf("revoked peer accessed new credentials: %+v", stats)
	}
	close(finish)
	if status := <-result; status != 200 {
		t.Fatalf("in-flight old snapshot lost: %d", status)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = h.snapshot.WaitDrained(ctx); err != nil {
		t.Fatal(err)
	}
	h.eventsMu.Lock()
	defer h.eventsMu.Unlock()
	revisions := map[string]string{}
	for _, event := range h.events {
		revisions[event.Snapshot] = event.PolicyRevision
	}
	if revisions["v1"] != "p1" || revisions["v2"] != "p2" {
		t.Fatalf("mixed snapshot metadata: %+v", revisions)
	}
}

func TestTLSAndExecutionBounds(t *testing.T) {
	t.Run("untrusted certificate", func(t *testing.T) {
		var calls atomic.Int64
		h := newHarness(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }, true, Options{RootCAs: x509.NewCertPool()})
		status, _, body := h.request(t, "GET", "/upstreams/github/private", "", http.Header{})
		if status != 502 || calls.Load() != 0 || strings.Contains(body, testToken) {
			t.Fatalf("unverified upstream accepted: status=%d calls=%d", status, calls.Load())
		}
	})
	t.Run("concurrency and deadline", func(t *testing.T) {
		started := make(chan struct{})
		canceled := make(chan struct{})
		var calls atomic.Int64
		h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
			io.Copy(io.Discard, r.Body)
			calls.Add(1)
			close(started)
			<-r.Context().Done()
			close(canceled)
		}, true, Options{MaxConcurrent: 1, RequestTimeout: 300 * time.Millisecond})
		result := make(chan int, 1)
		go func() {
			r, err := h.client.Get("http://pdp/upstreams/github/slow")
			if err != nil {
				result <- 0
				return
			}
			defer r.Body.Close()
			io.Copy(io.Discard, r.Body)
			result <- r.StatusCode
		}()
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("request did not start")
		}
		status, _, _ := h.request(t, "GET", "/upstreams/github/other", "", http.Header{})
		if status != 503 || calls.Load() != 1 {
			t.Fatalf("concurrency bound exceeded status=%d calls=%d", status, calls.Load())
		}
		select {
		case status := <-result:
			if status != 502 {
				t.Fatalf("deadline response status=%d", status)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("request exceeded deadline")
		}
		select {
		case <-canceled:
		case <-time.After(time.Second):
			t.Fatal("upstream request was not canceled")
		}
	})
}

func TestSchemaPolicyInput(t *testing.T) {
	spec, err := os.ReadFile("../schema/testdata/github-rest.json")
	if err != nil {
		t.Fatal(err)
	}
	rest, err := schema.CompileREST(spec)
	if err != nil {
		t.Fatal(err)
	}
	module, err := os.ReadFile("testdata/repository.rego")
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}, true, Options{})
	install := func(version, task string) {
		t.Helper()
		data := map[string]any{
			"peer_uid":          os.Getuid(),
			"identity_tasks":    map[string]any{fmt.Sprintf("uid:%d", os.Getuid()): task},
			"task_repositories": map[string]any{"task-1": []any{"team/project"}},
		}
		engine := engineFor(t, "scoped-policy", string(module), data)
		s, err := NewSnapshot(SnapshotConfig{Version: version, Authenticator: auth.NewUnix(), Policy: engine, Credentials: managerFor(t, testToken), Routes: []Route{{Provider: "github", Binding: "installation", UpstreamURL: h.endpoint, REST: rest}}})
		if err != nil {
			t.Fatal(err)
		}
		if err = h.g.Reload(s); err != nil {
			t.Fatal(err)
		}
	}
	install("scoped-v1", "task-1")
	for _, test := range []struct {
		path   string
		status int
	}{
		{"/repos/team/project", 200},
		{"/repos/other/project", 403},
		{"/repos/team/project/issues/1/comments?per_page=10", 200},
		{"/repos/team/project/issues/1/comments?per_page=11", 403},
	} {
		status, _, _ := h.request(t, "GET", "/upstreams/github"+test.path, "", http.Header{})
		if status != test.status {
			t.Fatalf("%s: status %d", test.path, status)
		}
	}
	install("scoped-v2", "unlinked-task")
	status, _, _ := h.request(t, "GET", "/upstreams/github/repos/team/project", "", http.Header{"X-Task-Id": {"task-1"}})
	if status != 403 || calls.Load() != 2 {
		t.Fatalf("scope/task restriction bypass status=%d calls=%d", status, calls.Load())
	}
	h.eventsMu.Lock()
	defer h.eventsMu.Unlock()
	for _, event := range h.events {
		if event.Outcome == "forwarded" && (event.SchemaDigest != rest.Digest() || event.Principal != fmt.Sprintf("uid:%d", os.Getuid()) || len(event.MatchedRules) != 1) {
			t.Fatalf("incomplete audit snapshot: %+v", event)
		}
	}
}

func TestLinearGraphQLBoundary(t *testing.T) {
	sdl, err := os.ReadFile("../schema/testdata/linear.graphql")
	if err != nil {
		t.Fatal(err)
	}
	gql, err := schema.CompileGraphQL(sdl)
	if err != nil {
		t.Fatal(err)
	}
	module, err := os.ReadFile("testdata/linear.rego")
	if err != nil {
		t.Fatal(err)
	}
	engine := engineFor(t, "graphql-policy", string(module), map[string]any{"peer_uid": os.Getuid(), "issue_fields": map[string]any{"APP-1": []any{"Issue.id", "Issue.title"}}})
	var calls atomic.Int64
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.URL.Path != "/graphql" || r.Header.Get("Authorization") != "Bearer "+testToken {
			t.Error("Linear destination or credential changed")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"issue":{"id":"APP-1","title":"read"}}}`)
	}, true, Options{})
	snapshot, err := NewSnapshot(SnapshotConfig{Version: "graphql-v1", Authenticator: auth.NewUnix(), Policy: engine, Credentials: managerForProvider(t, testToken, "linear"), Routes: []Route{{Provider: "linear", Binding: "installation", UpstreamURL: h.endpoint + "/graphql", GraphQL: gql}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = h.g.Reload(snapshot); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		body   string
		status int
	}{
		{`{"query":"query Read($id:String!){ alias:issue(id:$id){ id title } }","variables":{"id":"APP-1"}}`, 200},
		{`{"query":"{ a:issue(id:\"APP-1\"){ id } b:issue(id:\"APP-2\"){ id } }"}`, 403},
		{`{"query":"{ issue(id:\"APP-1\"){ title:description } }"}`, 403},
		{`[{"query":"{ issue(id:\"APP-1\"){ id } }"}]`, 400},
		{`{"query":"subscription { issue(id:\"APP-1\"){ id } }"}`, 400},
	} {
		status, _, _ := h.request(t, "POST", "/upstreams/linear/graphql", test.body, http.Header{})
		if status != test.status {
			t.Fatalf("GraphQL status=%d want=%d", status, test.status)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("denied GraphQL request forwarded: calls=%d", calls.Load())
	}
	changed, err := schema.CompileGraphQL([]byte(strings.Replace(string(sdl), "title: String!", "title: String", 1)))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err = NewSnapshot(SnapshotConfig{Version: "graphql-v2", Authenticator: auth.NewUnix(), Policy: engine, Credentials: managerForProvider(t, testToken, "linear"), Routes: []Route{{Provider: "linear", Binding: "installation", UpstreamURL: h.endpoint + "/graphql", GraphQL: changed}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = h.g.Reload(snapshot); err != nil {
		t.Fatal(err)
	}
	status, _, _ := h.request(t, "POST", "/upstreams/linear/graphql", `{"query":"{ issue(id:\"APP-1\") { id title } }"}`, http.Header{})
	if status != 403 || calls.Load() != 1 {
		t.Fatalf("schema digest pin bypassed: status=%d calls=%d", status, calls.Load())
	}
	if stats := h.g.Metrics().Credentials; stats.Hits != 0 || stats.Misses != 0 || stats.Acquisitions != 0 {
		t.Fatalf("schema-mismatched request accessed credentials: %+v", stats)
	}
}
