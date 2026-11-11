package gateway

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gfx-labs/pdp/pkg/credential"
)

// proxyClient is an unmodified Go HTTP client told to use the gateway as its
// proxy. For an https URL it sends CONNECT and then speaks TLS inside it.
func (h *harness) proxyClient(t *testing.T, roots *x509.CertPool) *http.Client {
	t.Helper()
	proxy, _ := url.Parse("http://pdp")
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), TLSClientConfig: &tls.Config{RootCAs: roots}, DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", h.socket)
		}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func get(t *testing.T, client *http.Client, target string) (int, string) {
	t.Helper()
	response, err := client.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(data)
}

// CONNECT is intercepted with a leaf from the administrator CA, so requests
// inside it are authorized one by one and get the credential like any other.
func TestConnectInterception(t *testing.T) {
	authority, clientRoots := testAuthority(t)
	var calls atomic.Int64
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			t.Error("credential was not injected inside the intercepted connection")
		}
		_, _ = io.WriteString(w, "intercepted")
	}, true, Options{Interception: authority})
	h.install(t, "paths", engineFor(t, "paths-policy", fmt.Sprintf(`package pdp.authz
import rego.v1
default allow := false
allow if {
	%s
	input.destination.host == "example.com"
	input.destination.scheme == "https"
	startswith(input.http.path, "/allowed/")
}
`, callerRule(true)), nil), managerFor(t, testToken), h.upstream())
	client := h.proxyClient(t, clientRoots)
	if status, body := get(t, client, h.base+"/allowed/x"); status != 200 || body != "intercepted" {
		t.Fatalf("intercepted request: status=%d body=%s", status, body)
	}
	if status, body := get(t, client, h.base+"/other"); status != 403 || strings.Contains(body, testToken) || calls.Load() != 1 {
		t.Fatalf("policy was not applied inside CONNECT: status=%d calls=%d", status, calls.Load())
	}
	// The tunnel was opened for example.com. A request inside it that names
	// another host must not be sent anywhere.
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	target := net.JoinHostPort(testHost, strconv.Itoa(h.port))
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	reader := bufio.NewReader(conn)
	established, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if err != nil || established.StatusCode != 200 {
		t.Fatalf("CONNECT: %v", err)
	}
	secured := tls.Client(conn, &tls.Config{RootCAs: clientRoots, ServerName: testHost})
	if err = secured.Handshake(); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(secured, "GET /allowed/x HTTP/1.1\r\nHost: other.test\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(secured), nil)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 400 || calls.Load() != 1 {
		t.Fatalf("Host inside CONNECT changed the destination: status=%d calls=%d", response.StatusCode, calls.Load())
	}
	// Without a CA the gateway cannot read the connection, so it refuses it.
	plain := newHarness(t, func(http.ResponseWriter, *http.Request) { t.Error("reached upstream without interception") }, true, Options{})
	if _, err = plain.proxyClient(t, clientRoots).Get(plain.base + "/allowed/x"); err == nil {
		t.Fatal("CONNECT accepted with no interception CA and no tunnel upstream")
	}
}

// A tunnel upstream is relayed unread: the client verifies the real server
// certificate, policy sees only host and port, and nothing is injected.
func TestOpaqueTunnel(t *testing.T) {
	var calls atomic.Int64
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Error("credential injected into an opaque tunnel")
		}
		_, _ = io.WriteString(w, "end to end")
	}, true, Options{})
	install := func(version string, port int) {
		h.install(t, version, engineFor(t, version, fmt.Sprintf(`package pdp.authz
import rego.v1
default allow := false
allow if {
	%s
	input.protocol == "tunnel"
	not input.http
	input.destination.scheme == "tcp"
	input.destination.host == "example.com"
	input.destination.port == %d
	not outside_loopback
}
outside_loopback if {
	some address in input.destination.addresses
	not net.cidr_contains("127.0.0.0/8", address)
}
`, callerRule(true), port), nil), managerFor(t, testToken), Upstream{Host: testHost, Port: h.port, Tunnel: true})
	}
	install("tunnel", h.port)
	client := h.proxyClient(t, h.roots)
	if status, body := get(t, client, h.base+"/x"); status != 200 || body != "end to end" {
		t.Fatalf("tunnel: status=%d body=%s", status, body)
	}
	// A tunnel upstream cannot be read, so a request that asks the gateway to
	// read it is refused instead of silently intercepted.
	if status, _, _ := h.request(t, "GET", "/x", "", http.Header{}); status != 400 {
		t.Fatalf("absolute-form request to a tunnel upstream: status=%d", status)
	}
	install("tunnel-denied", h.port+1)
	if _, err := client.Get(h.base + "/x"); err == nil || calls.Load() != 1 {
		t.Fatalf("denied tunnel was established: err=%v calls=%d", err, calls.Load())
	}
	events := h.audit()
	if last := events[len(events)-1]; last.Outcome != "forbidden" || last.Protocol != "tunnel" {
		t.Fatalf("denied tunnel audit: %+v", last)
	}
}

// The upgrade request is authorized and credentialed, then bytes are relayed.
func TestWebSocketRelay(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken || r.Header.Get("Sec-WebSocket-Key") != "dGhlIHNhbXBsZSBub25jZQ==" {
			w.WriteHeader(403)
			return
		}
		conn, buffered, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		io.WriteString(buffered, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		buffered.Flush()
		// Echo is enough to prove both directions are relayed after the upgrade.
		io.Copy(conn, buffered)
	}, true, Options{})
	h.install(t, "ws", engineFor(t, "ws-policy", fmt.Sprintf(`package pdp.authz
import rego.v1
default allow := false
allow if {
	%s
	input.protocol == "websocket"
	input.http.path == "/socket"
}
`, callerRule(true)), nil), managerFor(t, testToken), h.upstream())
	upgrade := func(path string) (*http.Response, *bufio.Reader, net.Conn) {
		t.Helper()
		conn, err := net.Dial("unix", h.socket)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprintf(conn, "GET %s%s HTTP/1.1\r\nHost: pdp\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nAuthorization: Bearer caller\r\n\r\n", h.base, path)
		reader := bufio.NewReader(conn)
		response, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		return response, reader, conn
	}
	response, reader, conn := upgrade("/socket")
	if response.StatusCode != 101 {
		t.Fatalf("upgrade status=%d", response.StatusCode)
	}
	if _, err := io.WriteString(conn, "frame-bytes"); err != nil {
		t.Fatal(err)
	}
	echoed := make([]byte, len("frame-bytes"))
	if _, err := io.ReadFull(reader, echoed); err != nil || string(echoed) != "frame-bytes" {
		t.Fatalf("relay after upgrade: %q %v", echoed, err)
	}
	conn.Close()
	if response, _, _ = upgrade("/elsewhere"); response.StatusCode != 403 {
		t.Fatalf("upgrade the policy does not allow: status=%d", response.StatusCode)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		events := h.audit()
		if len(events) == 2 && events[0].Outcome == "upgraded" && events[0].BytesSent == int64(len(echoed)) && events[0].BytesReceived == int64(len(echoed)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("upgrade audit: %+v", events)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A streamed response reaches the client as it is produced, and the injected
// credential is caught even when the upstream splits it across writes.
func TestStreamedResponse(t *testing.T) {
	release := make(chan struct{})
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		if r.URL.Path == "/events" {
			io.WriteString(w, "data: first\n\n")
			flusher.Flush()
			<-release
			io.WriteString(w, "data: second\n\n")
			return
		}
		io.WriteString(w, "data: before\n\n"+testToken[:10])
		flusher.Flush()
		io.WriteString(w, testToken[10:]+"\n\ndata: after\n\n")
	}, true, Options{})
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(conn, "GET %s/events HTTP/1.1\r\nHost: pdp\r\n\r\n", h.base)
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	first := make([]byte, len("data: first\n\n"))
	// The upstream is still holding the second event, so this read only
	// returns if the first one was relayed without buffering the response.
	if _, err = io.ReadFull(response.Body, first); err != nil || string(first) != "data: first\n\n" {
		t.Fatalf("first event was not relayed while the stream was open: %q %v", first, err)
	}
	close(release)
	rest, err := io.ReadAll(response.Body)
	if err != nil || string(rest) != "data: second\n\n" {
		t.Fatalf("rest of stream: %q %v", rest, err)
	}
	status, _, body, err := h.do("GET", "/reflects", "", http.Header{})
	if err == nil || status != 200 || strings.Contains(body, testToken[:10]) || strings.Contains(body, "after") {
		t.Fatalf("reflected credential was relayed: status=%d err=%v body=%q", status, err, body)
	}
	events := h.audit()
	if last := events[len(events)-1]; last.Outcome != "credential_reflected" || last.Status != 502 {
		t.Fatalf("reflection audit: %+v", last)
	}
}

// Two accounts share one host. The placeholder picks the candidate binding,
// and policy decides whether this caller may use it.
func TestPlaceholderBindings(t *testing.T) {
	const placeholderA, placeholderB = "pdp-placeholder-account-a", "pdp-placeholder-account-b"
	const tokenA, tokenB = "real-access-token-account-a-91c2", "real-access-token-account-b-5d7e"
	var calls atomic.Int64
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+tokenA || r.Header.Get("X-Account-Id") != "account-a" || r.Header.Get("X-Api-Key") != "" {
			t.Errorf("auth fields were not all replaced: %v", r.Header)
		}
		_, _ = io.WriteString(w, "account a")
	}, true, Options{})
	dir := t.TempDir()
	bindings := map[string]credential.BindingConfig{}
	for name, account := range map[string][3]string{"account-a": {tokenA, placeholderA, "account-a"}, "account-b": {tokenB, placeholderB, "account-b"}} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(account[0]), 0600); err != nil {
			t.Fatal(err)
		}
		bindings[name] = credential.BindingConfig{Provider: "provider", Placeholder: account[1], Headers: map[string]string{"X-Account-Id": account[2]}, Secrets: map[string]credential.SecretSource{"token": {File: path}}}
	}
	manager, err := credential.New(credential.Config{
		Providers: map[string]credential.ProviderConfig{"provider": {Script: "def acquire(ctx):\n    return static(secret(\"token\"))\n"}},
		Bindings:  bindings,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.install(t, "accounts", engineFor(t, "accounts-policy", fmt.Sprintf(`package pdp.authz
import rego.v1
default allow := false
allow if {
	%s
	input.destination.host == "example.com"
	input.binding in data.granted
}
`, callerRule(true)), map[string]any{"granted": []any{"account-a"}}), manager,
		Upstream{Host: testHost, Port: h.port, Bindings: []string{"account-a", "account-b"}, TokenPaths: []string{"/oauth/token"}})
	asAccount := func(placeholder string) http.Header {
		return http.Header{"Authorization": {"Bearer " + placeholder}, "X-Account-Id": {"caller-chosen"}, "X-Api-Key": {placeholder}}
	}
	if status, _, body := h.request(t, "GET", "/v1/models", "", asAccount(placeholderA)); status != 200 || body != "account a" {
		t.Fatalf("granted account: status=%d body=%s", status, body)
	}
	// The other account's placeholder is known to the caller but not granted.
	if status, _, _ := h.request(t, "GET", "/v1/models", "", asAccount(placeholderB)); status != 403 {
		t.Fatalf("ungranted account's placeholder was accepted: status=%d", status)
	}
	if status, _, _ := h.request(t, "GET", "/v1/models", "", http.Header{"Authorization": {"Bearer something-else"}}); status != 403 {
		t.Fatalf("request with no placeholder: status=%d", status)
	}
	form := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	status, _, body := h.request(t, "POST", "/oauth/token", "grant_type=refresh_token&refresh_token="+placeholderA, form)
	if status != 200 || !strings.Contains(body, `"access_token":"`+placeholderA+`"`) || !strings.Contains(body, `"expires_in":3600`) || strings.Contains(body, tokenA) {
		t.Fatalf("token request was not answered with the placeholder: status=%d body=%s", status, body)
	}
	if status, _, body = h.request(t, "POST", "/oauth/token", "grant_type=refresh_token&refresh_token="+placeholderB, form); status != 403 || strings.Contains(body, placeholderB) {
		t.Fatalf("token request for an ungranted account: status=%d body=%s", status, body)
	}
	if calls.Load() != 1 {
		t.Fatalf("a denied or token request reached the provider: calls=%d", calls.Load())
	}
	if stats := h.g.Metrics().Credentials; stats.Acquisitions != 1 {
		t.Fatalf("credentials acquired for denied or token requests: %+v", stats)
	}
}

// A DNS-steered client connects as if to the destination. The gateway reads
// the destination from SNI and Host and knows the caller only by address.
func TestTransparentListener(t *testing.T) {
	authority, clientRoots := testAuthority(t)
	var calls atomic.Int64
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.WriteString(w, "steered")
	}, true, Options{Interception: authority})
	// The Unix rule must not apply: this caller has no UID, only an address.
	h.install(t, "steered", engineFor(t, "steered-policy", fmt.Sprintf(`package pdp.authz
import rego.v1
default allow := false
allow if {
	%s
}
allow if {
	input.identity == {"id": "ip:127.0.0.1", "auth_method": "transparent", "ip": "127.0.0.1"}
	input.destination.scheme == "https"
	input.destination.host == "example.com"
	input.destination.port == 443
	input.http.path == "/steered"
}
`, callerRule(true)), nil), managerFor(t, testToken), Upstream{Host: "unused.test"})
	// The steered client asks for port 443. Send that to the test upstream.
	h.g.opts.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, h.address)
	}
	tlsConfig, err := h.g.TransparentTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := NewTransparentServer("", h.g)
	go server.Serve(tls.NewListener(tcp, tlsConfig))
	t.Cleanup(func() { server.Close() })
	request := func(sni, host, path string) int {
		t.Helper()
		conn, err := tls.Dial("tcp", tcp.Addr().String(), &tls.Config{RootCAs: clientRoots, ServerName: sni})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host)
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		return response.StatusCode
	}
	if status := request(testHost, testHost, "/steered"); status != 200 || calls.Load() != 1 {
		t.Fatalf("steered request: status=%d calls=%d", status, calls.Load())
	}
	if status := request(testHost, testHost, "/other"); status != 403 {
		t.Fatalf("steered request the policy does not allow: status=%d", status)
	}
	// The certificate was minted for the SNI name, so Host cannot name another.
	if status := request(testHost, "other.test", "/steered"); status != 400 || calls.Load() != 1 {
		t.Fatalf("Host disagreed with SNI: status=%d calls=%d", status, calls.Load())
	}
}
