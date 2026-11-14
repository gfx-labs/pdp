package gateway

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gfx-labs/pdp/pkg/auth"
	"github.com/gfx-labs/pdp/pkg/credential"
	"github.com/gfx-labs/pdp/pkg/intercept"
	"github.com/gfx-labs/pdp/pkg/policy"
	"github.com/gfx-labs/pdp/pkg/schema"
)

const testToken = "pdp-test-provider-secret-7b35ef91"

// httptest's server certificate names this host, so TLS to it verifies.
const testHost = "example.com"

type harness struct {
	g        *Gateway
	snapshot *Snapshot
	socket   string
	roots    *x509.CertPool
	port     int
	base     string
	address  string
	mu       sync.Mutex
	events   []AuditEvent
	lookups  []string
}

// testAuth identifies steered connections by address and all others by Unix peer.
type testAuth struct{}

func (testAuth) Authenticate(r *http.Request) (auth.Identity, error) {
	if auth.IsTransparent(r.Context()) {
		return auth.Transparent{}.Authenticate(r)
	}
	return auth.NewUnix().Authenticate(r)
}

func callerRule(allow bool) string {
	uid := os.Getuid()
	if !allow {
		uid++
	}
	return fmt.Sprintf("input.identity.auth_method == \"unix\"\n\tinput.identity.uid == %d", uid)
}

func policyFor(t *testing.T, version string, allow bool) *policy.Engine {
	t.Helper()
	return engineFor(t, version, fmt.Sprintf(`package pdp.authz
import rego.v1
default allow := false
allow if {
	%s
	input.destination.host == "example.com"
	input.binding == "installation"
}
matched_rules contains "authenticated-peer" if allow
`, callerRule(allow)), nil)
}

func engineFor(t *testing.T, version, module string, data map[string]any) *policy.Engine {
	t.Helper()
	engine, err := policy.New(context.Background(), policy.Config{Revision: version, Modules: map[string]string{"authz.rego": module}, Data: data})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func managerFor(t *testing.T, token string) *credential.Manager {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	manager, err := credential.New(credential.Config{
		Providers: map[string]credential.ProviderConfig{"provider": {Script: "def acquire(ctx):\n    return static(secret(\"token\"))\n"}},
		Bindings:  map[string]credential.BindingConfig{"installation": {Provider: "provider", Secrets: map[string]credential.SecretSource{"token": {File: path}}}},
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
	h := &harness{roots: x509.NewCertPool(), address: upstream.Listener.Addr().String()}
	h.roots.AddCert(upstream.Certificate())
	_, port, _ := net.SplitHostPort(h.address)
	h.port, _ = strconv.Atoi(port)
	h.base = "https://" + net.JoinHostPort(testHost, port)
	if options.RootCAs == nil {
		options.RootCAs = h.roots
	}
	// Every test name resolves to the local upstream. Looked-up names are recorded.
	options.Lookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		h.mu.Lock()
		h.lookups = append(h.lookups, host)
		h.mu.Unlock()
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	options.Audit = func(event AuditEvent) { h.mu.Lock(); h.events = append(h.events, event); h.mu.Unlock() }
	snapshot, err := NewSnapshot(SnapshotConfig{Version: "v1", Authenticator: testAuth{}, Policy: policyFor(t, "p1", allow), Credentials: managerFor(t, testToken), Upstreams: []Upstream{h.upstream()}})
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
	return h
}

func (h *harness) upstream() Upstream {
	return Upstream{Host: testHost, Port: h.port, Bindings: []string{"installation"}}
}

func (h *harness) install(t *testing.T, version string, engine *policy.Engine, credentials *credential.Manager, upstreams ...Upstream) {
	t.Helper()
	h.installAuth(t, version, testAuth{}, engine, credentials, upstreams...)
}

func (h *harness) installAuth(t *testing.T, version string, authenticator auth.Authenticator, engine *policy.Engine, credentials *credential.Manager, upstreams ...Upstream) {
	t.Helper()
	s, err := NewSnapshot(SnapshotConfig{Version: version, Authenticator: authenticator, Policy: engine, Credentials: credentials, Upstreams: upstreams})
	if err != nil {
		t.Fatal(err)
	}
	if err = h.g.Reload(s); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) audit() []AuditEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]AuditEvent(nil), h.events...)
}

// do sends one absolute-form request over the Unix socket. A target starting
// with a slash is a path on the test upstream. It returns what was read even
// when the gateway cut the response short.
func (h *harness) do(method, target, body string, headers http.Header) (int, http.Header, string, error) {
	if strings.HasPrefix(target, "/") {
		target = h.base + target
	}
	r, err := http.NewRequest(method, target, strings.NewReader(body))
	if err != nil {
		return 0, nil, "", err
	}
	for name, values := range headers {
		r.Header[name] = values
	}
	if body != "" && r.Header.Get("Content-Type") == "" {
		r.Header.Set("Content-Type", "application/json")
	}
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		return 0, nil, "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err = r.WriteProxy(conn); err != nil {
		return 0, nil, "", err
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), r)
	if err != nil {
		return 0, nil, "", err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	return response.StatusCode, response.Header, string(data), err
}

func (h *harness) request(t *testing.T, method, target, body string, headers http.Header) (int, http.Header, string) {
	t.Helper()
	status, header, data, err := h.do(method, target, body, headers)
	if err != nil {
		t.Fatal(err)
	}
	return status, header, data
}

func restSchema(t *testing.T) *schema.RESTSchema {
	t.Helper()
	spec, err := os.ReadFile("../schema/testdata/github-rest.json")
	if err != nil {
		t.Fatal(err)
	}
	rest, err := schema.CompileREST(spec)
	if err != nil {
		t.Fatal(err)
	}
	return rest
}

// installREST pins the reviewed REST schema on the test upstream.
func (h *harness) installREST(t *testing.T) {
	t.Helper()
	up := h.upstream()
	up.Plugin, up.REST = "github", restSchema(t)
	h.install(t, "rest", policyFor(t, "rest-policy", true), managerFor(t, testToken), up)
}

// testAuthority writes a CA to disk and loads it the way a deployment would.
func testAuthority(t *testing.T) (*intercept.Authority, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "pdp test interception CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certificateFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err = os.WriteFile(certificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0600); err != nil {
		t.Fatal(err)
	}
	authority, err := intercept.Load(certificateFile, keyFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return authority, roots
}

// These tests use kernel-authenticated Unix clients, the real policy/adapter
// pipeline and verified TLS endpoints. They protect the gateway boundary itself.
func TestUnixTLSForward(t *testing.T) {
	var calls atomic.Int64
	var redirected atomic.Int64
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
	defer elsewhere.Close()
	var h *harness
	h = newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.TLS == nil || r.Host != net.JoinHostPort(testHost, strconv.Itoa(h.port)) {
			t.Error("destination was not fixed")
		}
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			t.Error("credential injection failed")
		}
		for _, name := range []string{"Cookie", "Proxy-Authorization", "X-Custom-Hop"} {
			if r.Header.Get(name) != "" {
				t.Errorf("caller header forwarded: %s", name)
			}
		}
		switch r.URL.Path {
		case "/reflected-header":
			w.Header().Set("X-Debug", testToken)
		case "/redirect":
			w.Header().Set("Location", elsewhere.URL)
			w.WriteHeader(302)
			return
		}
		_, _ = io.WriteString(w, "plain text, not JSON")
	}, true, Options{})
	headers := http.Header{"Authorization": {"Bearer caller"}, "Cookie": {"caller-secret"}, "Proxy-Authorization": {"caller-proxy"}, "Connection": {"X-Custom-Hop"}, "X-Custom-Hop": {"untrusted"}}
	status, _, body := h.request(t, "GET", "/repos/team/project/issues?state=open", "", headers)
	if status != 200 || body != "plain text, not JSON" || calls.Load() != 1 {
		t.Fatalf("status=%d body=%s calls=%d", status, body, calls.Load())
	}
	var response http.Header
	if status, _, body = h.request(t, "GET", "/reflected-header", "", http.Header{}); status != 502 || strings.Contains(body, testToken) {
		t.Fatalf("credential reflected in a response header: status=%d", status)
	}
	// A redirect goes back to the caller, whose next request is authorized on its own.
	if status, response, _ = h.request(t, "GET", "/redirect", "", http.Header{}); status != 302 || response.Get("Location") != elsewhere.URL || redirected.Load() != 0 {
		t.Fatalf("redirect was followed or dropped: status=%d", status)
	}
	audit, _ := json.Marshal(h.audit())
	if strings.Contains(string(audit), testToken) || strings.Contains(string(audit), "caller-secret") || strings.Contains(string(audit), "/repos/") || strings.Contains(string(audit), "state=open") {
		t.Fatalf("audit contains request values: %s", audit)
	}
	if first := h.audit()[0]; first.Host != testHost || first.Port != h.port || first.Binding != "installation" || first.Protocol != "http" || first.Outcome != "forwarded" {
		t.Fatalf("audit does not name the destination: %+v", first)
	}
	metrics := h.g.Metrics()
	if metrics.Requests != 3 || metrics.Allowed != 2 || metrics.Failed != 1 {
		t.Fatalf("metrics: %+v", metrics)
	}
}

func TestDeniedNeverForwards(t *testing.T) {
	var calls atomic.Int64
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }, false, Options{})
	status, _, body := h.request(t, "GET", "/repos/team/project", "", http.Header{"Authorization": {"Bearer trusted"}, "X-Principal": {"alice"}, "X-Uid": {fmt.Sprint(os.Getuid() + 1)}, "X-Spiffe-Id": {"spiffe://example.test/admin"}})
	if status != 403 || calls.Load() != 0 || strings.Contains(body, testToken) {
		t.Fatalf("denied request crossed boundary: status=%d calls=%d body=%s", status, calls.Load(), body)
	}
	// A TCP request cannot acquire Unix identity from headers or a remote address.
	tcp := httptest.NewServer(h.g)
	defer tcp.Close()
	proxy, _ := url.Parse(tcp.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}, Timeout: 3 * time.Second}
	response, err := client.Get("http://" + net.JoinHostPort(testHost, strconv.Itoa(h.port)) + "/repos/team/project")
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
	if len(h.lookups) != 0 {
		t.Fatalf("denied destination was resolved: %v", h.lookups)
	}
}

// A destination nobody configured still goes to policy, which is the only
// allowlist. It gets no credential, and denied names are never resolved.
func TestUnlistedDestinationsAreDecidedByPolicy(t *testing.T) {
	var calls atomic.Int64
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer callers-own" {
			t.Errorf("unlisted destination received another credential: %q", r.Header.Get("Authorization"))
		}
		_, _ = io.WriteString(w, "open")
	}, true, Options{})
	h.install(t, "open", engineFor(t, "open-policy", fmt.Sprintf(`package pdp.authz
import rego.v1
default allow := false
caller if {
	%s
}
allow if {
	caller
	input.destination.host == "127.0.0.1"
	input.http.method == "GET"
	not input.binding
}
allow if {
	caller
	input.destination.host == "rebind.test"
	not loopback
}
loopback if {
	some address in input.destination.addresses
	net.cidr_contains("127.0.0.0/8", address)
}
`, callerRule(true)), nil), managerFor(t, testToken), h.upstream())
	literal := "https://" + h.address
	own := http.Header{"Authorization": {"Bearer callers-own"}}
	if status, _, body := h.request(t, "GET", literal+"/anything", "", own); status != 200 || body != "open" {
		t.Fatalf("policy-allowed unlisted destination: status=%d body=%s", status, body)
	}
	if status, _, _ := h.request(t, "POST", literal+"/anything", "{}", own); status != 403 {
		t.Fatalf("method the policy does not allow: status=%d", status)
	}
	if status, _, _ := h.request(t, "GET", "https://Denied.Test./x", "", own); status != 403 || len(h.lookups) != 0 {
		t.Fatalf("refused name was resolved or allowed: status=%d lookups=%v", status, h.lookups)
	}
	// Allowed by name, refused once policy sees the address it resolves to.
	if status, _, _ := h.request(t, "GET", "https://rebind.test:"+strconv.Itoa(h.port)+"/x", "", own); status != 403 || len(h.lookups) != 1 || h.lookups[0] != "rebind.test" {
		t.Fatalf("resolved address was not shown to policy: status=%d lookups=%v", status, h.lookups)
	}
	if calls.Load() != 1 {
		t.Fatalf("denied request reached a destination: calls=%d", calls.Load())
	}
	if stats := h.g.Metrics().Credentials; stats.Acquisitions != 0 {
		t.Fatalf("credential acquired for an unlisted destination: %+v", stats)
	}
}

func TestAmbiguitiesNeverForward(t *testing.T) {
	var calls atomic.Int64
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}, true, Options{MaxRequestBytes: 128})
	h.installREST(t)
	const repo, comments = "/repos/team/project", "/repos/team/project/issues/1/comments"
	if status, _, _ := h.request(t, "GET", repo, "", http.Header{}); status != 200 || calls.Load() != 1 {
		t.Fatalf("unambiguous request: status=%d", status)
	}
	cases := []struct {
		name, method, path, body string
		headers                  http.Header
	}{
		{"encoded slash", "GET", "/repos/team%2Fproject", "", nil},
		{"double slash", "GET", "/repos//project", "", nil},
		{"dot segment", "GET", "/repos/team/../project", "", nil},
		{"duplicate query", "GET", comments + "?per_page=1&%70er_page=2", "", nil},
		{"empty query part", "GET", comments + "?per_page=1&&page=2", "", nil},
		{"missing query equals", "GET", comments + "?per_page", "", nil},
		{"JSON duplicate", "POST", comments, `{"body":"a","body":"b"}`, nil},
		{"JSON trailing", "POST", comments, `{"body":"a"} {}`, nil},
		{"body array", "POST", comments, `[{"body":"a"}]`, nil},
		{"encoding", "POST", comments, `{"body":"a"}`, http.Header{"Content-Encoding": {"gzip"}}},
		{"upgrade", "GET", repo, "", http.Header{"Connection": {"upgrade"}, "Upgrade": {"websocket"}}},
		{"body limit", "POST", comments, `{"body":"` + strings.Repeat("x", 130) + `"}`, nil},
		{"plaintext scheme", "GET", "http://" + net.JoinHostPort(testHost, strconv.Itoa(h.port)) + repo, "", nil},
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
	target := h.base + comments
	for _, raw := range []string{
		"POST " + target + " HTTP/1.1\r\nHost: pdp\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\nc\r\n{\"body\":\"a\"}\r\n0\r\n\r\n",
		"POST " + target + " HTTP/1.1\r\nHost: pdp\r\nContent-Type: application/json\r\nContent-Type: application/json\r\nContent-Length: 12\r\n\r\n{\"body\":\"a\"}",
	} {
		conn, err := net.Dial("unix", h.socket)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err = io.WriteString(conn, raw); err != nil {
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
	if calls.Load() != 1 {
		t.Fatalf("invalid request reached upstream %d times", calls.Load())
	}
}

func TestResponseBoundary(t *testing.T) {
	var targetCalls atomic.Int64
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalls.Add(1) }))
	defer redirect.Close()
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch strings.TrimPrefix(r.URL.Path, "/repos/case/") {
		case "redirect":
			w.Header().Set("Location", redirect.URL)
			w.WriteHeader(302)
		case "large":
			_, _ = io.WriteString(w, strings.Repeat("x", 257))
		case "stream":
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: secret\n")
		case "compressed":
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = io.WriteString(w, "not gzip")
		case "error":
			w.WriteHeader(400)
			_, _ = fmt.Fprintf(w, `{"error":%q}`, r.Header.Get("Authorization"))
		case "safe-error":
			w.WriteHeader(400)
			_, _ = io.WriteString(w, `{"errors":[{"message":"invalid field"}]}`)
		case "reflect":
			_, _ = fmt.Fprintf(w, `{"debug":%q}`, r.Header.Get("Authorization"))
		case "escaped", "escaped-error":
			if strings.HasSuffix(r.URL.Path, "-error") {
				w.WriteHeader(400)
			}
			_, _ = io.WriteString(w, `{"debug":"`+strings.ReplaceAll(testToken, "p", `\u0070`)+`"}`)
		case "malformed", "malformed-error":
			if strings.HasSuffix(r.URL.Path, "-error") {
				w.WriteHeader(400)
			}
			_, _ = io.WriteString(w, `not-json {"debug":"`+strings.ReplaceAll(testToken, "p", `\u0070`)+`"}`)
		}
	}, true, Options{MaxResponseBytes: 256})
	h.installREST(t)
	for _, path := range []string{"redirect", "large", "stream", "compressed", "reflect", "escaped", "malformed", "error", "escaped-error", "malformed-error"} {
		t.Run(path, func(t *testing.T) {
			status, headers, body := h.request(t, "GET", "/repos/case/"+path, "", http.Header{})
			if status != 502 || strings.Contains(body, testToken) || headers.Get("Location") != "" {
				t.Fatalf("status=%d body=%s", status, body)
			}
		})
	}
	status, _, body := h.request(t, "GET", "/repos/case/safe-error", "", http.Header{})
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
		if _, err := io.WriteString(conn, "GET "+h.base+"/warm HTTP/1.1\r\nHost: pdp\r\n\r\n"); err != nil {
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
		status, _, _, _ := h.do("GET", "/hold", "", http.Header{})
		result <- status
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not start")
	}
	h.install(t, "v2", policyFor(t, "p2", false), managerFor(t, "rotated-provider-token"), h.upstream())
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
	revisions := map[string]string{}
	for _, event := range h.audit() {
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
		status, _, body := h.request(t, "GET", "/private", "", http.Header{})
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
			status, _, _, _ := h.do("GET", "/slow", "", http.Header{})
			result <- status
		}()
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("request did not start")
		}
		status, _, _ := h.request(t, "GET", "/other", "", http.Header{})
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
	rest := restSchema(t)
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
		up := h.upstream()
		up.Plugin, up.REST = "github", rest
		h.install(t, version, engineFor(t, "scoped-policy", string(module), data), managerFor(t, testToken), up)
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
		status, _, _ := h.request(t, "GET", test.path, "", http.Header{})
		if status != test.status {
			t.Fatalf("%s: status %d", test.path, status)
		}
	}
	install("scoped-v2", "unlinked-task")
	status, _, _ := h.request(t, "GET", "/repos/team/project", "", http.Header{"X-Task-Id": {"task-1"}})
	if status != 403 || calls.Load() != 2 {
		t.Fatalf("scope/task restriction bypass status=%d calls=%d", status, calls.Load())
	}
	for _, event := range h.audit() {
		if event.Outcome == "forwarded" && (event.SchemaDigest != rest.Digest() || event.Plugin != "github" || event.Principal != fmt.Sprintf("uid:%d", os.Getuid()) || len(event.MatchedRules) != 1) {
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
	up := h.upstream()
	up.Plugin, up.GraphQL = "linear", gql
	h.install(t, "graphql-v1", engine, managerFor(t, testToken), up)
	for _, test := range []struct {
		path, body string
		status     int
	}{
		{"/graphql", `{"query":"query Read($id:String!){ alias:issue(id:$id){ id title } }","variables":{"id":"APP-1"}}`, 200},
		{"/graphql", `{"query":"{ a:issue(id:\"APP-1\"){ id } b:issue(id:\"APP-2\"){ id } }"}`, 403},
		{"/graphql", `{"query":"{ issue(id:\"APP-1\"){ title:description } }"}`, 403},
		{"/graphql", `[{"query":"{ issue(id:\"APP-1\"){ id } }"}]`, 400},
		{"/graphql", `{"query":"subscription { issue(id:\"APP-1\"){ id } }"}`, 400},
		{"/other", `{"query":"{ issue(id:\"APP-1\"){ id } }"}`, 400},
	} {
		status, _, _ := h.request(t, "POST", test.path, test.body, http.Header{})
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
	up.GraphQL = changed
	h.install(t, "graphql-v2", engine, managerFor(t, testToken), up)
	status, _, _ := h.request(t, "POST", "/graphql", `{"query":"{ issue(id:\"APP-1\") { id title } }"}`, http.Header{})
	if status != 403 || calls.Load() != 1 {
		t.Fatalf("schema digest pin bypassed: status=%d calls=%d", status, calls.Load())
	}
	if stats := h.g.Metrics().Credentials; stats.Hits != 0 || stats.Misses != 0 || stats.Acquisitions != 0 {
		t.Fatalf("schema-mismatched request accessed credentials: %+v", stats)
	}
}
