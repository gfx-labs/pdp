//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
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
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gfx-labs/pdp/pkg/auth"
	"github.com/gfx-labs/pdp/pkg/config"
	"github.com/gfx-labs/pdp/pkg/gateway"
)

const packRoot = "../../examples/packs"

type packRequest struct {
	method string
	url    string
	body   string // file under the pack's requests directory
	status int
}

// Owns the claim that each checked-in pack is usable as shipped. It serves the
// pack's own policy.rego, schema and adapter on a real Unix socket against a
// local TLS provider, changing only deployment values: socket, secret paths,
// token endpoints and the allowed UID. Upstream hosts stay as shipped. The
// test resolves them to the local provider, which holds a certificate for them.
func TestPacksServeTheirRequests(t *testing.T) {
	const repo = "https://api.github.com/repos/APPROVED_OWNER/APPROVED_REPOSITORY"
	const other = "https://api.github.com/repos/UNAPPROVED_OWNER/APPROVED_REPOSITORY"
	const linear = "https://api.linear.app/graphql"
	packs := map[string][]packRequest{
		"minimal": {
			{"GET", repo, "", 200},
		},
		"github-read": {
			{"GET", repo, "", 200},
			{"GET", repo + "/issues/123", "", 200},
			{"GET", repo + "/issues/123/comments?per_page=10", "", 200},
			{"GET", other, "", 403},
			{"POST", repo + "/issues/123/comments", "create-comment.json", 403},
		},
		"github-comment": {
			{"GET", repo, "", 200},
			{"POST", repo + "/issues/123/comments", "create-comment.json", 200},
			{"POST", other + "/issues/123/comments", "create-comment.json", 403},
		},
		"linear-read": {
			{"POST", linear, "read-issue.json", 200},
			{"POST", linear, "read-mixed-scope.json", 403},
			{"POST", linear, "create-comment.json", 403},
		},
		"linear-comment": {
			{"POST", linear, "read-issue.json", 200},
			{"POST", linear, "create-comment.json", 200},
			{"POST", linear, "read-mixed-scope.json", 403},
			{"POST", linear, "reject-alternate-target.json", 403},
		},
	}
	for name, requests := range packs {
		t.Run(name, func(t *testing.T) {
			servePack(t, name, os.Getuid(), requests)
		})
		// The same pack with a policy naming another UID denies its first request.
		t.Run(name+"/other-uid", func(t *testing.T) {
			denied := requests[0]
			denied.status = 403
			servePack(t, name, os.Getuid()+1, []packRequest{denied})
		})
	}
}

func servePack(t *testing.T, name string, allowedUID int, requests []packRequest) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.CopyFS(dir, os.DirFS(filepath.Join(packRoot, name))); err != nil {
		t.Fatal(err)
	}
	const token = "local-pack-test-token"
	var exchanges, forwarded atomic.Int64
	provider := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/access_tokens"):
			exchanges.Add(1)
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(map[string]any{"token": token, "expires_at": time.Now().Add(time.Hour), "permissions": map[string]string{"contents": "read", "issues": "write"}})
		case r.URL.Path == "/oauth/token":
			exchanges.Add(1)
			json.NewEncoder(w).Encode(map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 3600, "refresh_token": "local-pack-test-rotated"})
		case r.Header.Get("Authorization") == "Bearer "+token:
			forwarded.Add(1)
			io.Copy(io.Discard, r.Body)
			io.WriteString(w, `{"local_provider":true}`)
		default:
			w.WriteHeader(500)
		}
	}))
	certificate, root := providerCertificate(t, "api.github.com", "api.linear.app")
	provider.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	provider.StartTLS()
	defer provider.Close()

	// Deployment values only. Policy, schema and adapter stay as shipped.
	policyPath := filepath.Join(dir, "policy.rego")
	source, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	const shipped = "allowed_uids := {1000}"
	if !bytes.Contains(source, []byte(shipped)) {
		t.Fatalf("pack %s policy does not declare %s", name, shipped)
	}
	source = bytes.Replace(source, []byte(shipped), fmt.Appendf(nil, "allowed_uids := {%d}", allowedUID), 1)
	if err = os.WriteFile(policyPath, source, 0600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "pdp.json")
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err = json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "pdp.sock")
	document["transport"] = map[string]any{"unix_socket": socket, "socket_mode": "0600"}
	ca := filepath.Join(dir, "ca.pem")
	if err = os.WriteFile(ca, root, 0600); err != nil {
		t.Fatal(err)
	}
	document["ca_file"] = ca
	credentials := document["credentials"].(map[string]any)
	for providerName, entry := range credentials["providers"].(map[string]any) {
		endpoints, ok := entry.(map[string]any)["endpoints"].(map[string]any)
		if !ok {
			continue
		}
		endpoints["token"] = provider.URL + "/oauth/token"
		if providerName == "github" {
			endpoints["token"] = provider.URL + "/app/installations/1/access_tokens"
		}
	}
	for _, entry := range credentials["bindings"].(map[string]any) {
		binding := entry.(map[string]any)
		for alias, selector := range binding["secrets"].(map[string]any) {
			content := []byte(token)
			if alias == "private_key" {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
				content = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
			}
			path := filepath.Join(dir, "secret-"+alias)
			if err = os.WriteFile(path, content, 0600); err != nil {
				t.Fatal(err)
			}
			selector.(map[string]any)["file"] = path
		}
		if _, ok := binding["state_file"]; ok {
			state := filepath.Join(dir, "state.json")
			initial, _ := json.Marshal(map[string]any{"refresh_token": "local-pack-test-initial", "scopes": binding["scopes"]})
			if err = os.WriteFile(state, initial, 0600); err != nil {
				t.Fatal(err)
			}
			binding["state_file"] = state
		}
	}
	if raw, err = json.Marshal(document); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(configPath, raw, 0600); err != nil {
		t.Fatal(err)
	}

	loaded, err := config.Load(context.Background(), configPath)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	s, err := snapshot(loaded, combinedAuth{unix: auth.NewUnix()})
	if err != nil {
		t.Fatal(err)
	}
	options, err := gatewayOptions(loaded, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	providerAddress := provider.Listener.Addr().String()
	options.Lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	options.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, providerAddress)
	}
	g, err := gateway.New(s, options)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	listener, err := auth.ListenUnix(socket, 0600)
	if err != nil {
		t.Fatal(err)
	}
	server := gateway.NewHTTPServer("", g)
	go server.Serve(listener)
	defer server.Close()
	for _, want := range requests {
		var body []byte
		if want.body != "" {
			if body, err = os.ReadFile(filepath.Join(dir, "requests", want.body)); err != nil {
				t.Fatal(err)
			}
		}
		request, err := http.NewRequest(want.method, want.url, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		exchangesBefore, forwardedBefore := exchanges.Load(), forwarded.Load()
		response, err := proxyRequest(socket, request)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(response.Body)
		response.Body.Close()
		label := fmt.Sprintf("%s %s %s", want.method, want.url, want.body)
		if response.StatusCode != want.status {
			t.Fatalf("%s: HTTP %d, want %d: %s", label, response.StatusCode, want.status, data)
		}
		if bytes.Contains(data, []byte(token)) {
			t.Fatalf("%s: credential in response", label)
		}
		if want.status == 200 && forwarded.Load() != forwardedBefore+1 {
			t.Fatalf("%s: allowed request did not reach the provider", label)
		}
		if want.status != 200 && (forwarded.Load() != forwardedBefore || exchanges.Load() != exchangesBefore) {
			t.Fatalf("%s: denied request reached the provider or acquired a credential", label)
		}
	}
}

// providerCertificate is a self-signed certificate for the pack's upstream
// hosts and for loopback, where the token endpoints are pointed.
func providerCertificate(t *testing.T, hosts ...string) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "pdp pack test provider"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), DNSNames: hosts, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// packConfig is the pack's one configuration file, pdp.yaml or pdp.json.
func packConfig(t *testing.T, name string) string {
	t.Helper()
	var matches []string
	for _, file := range []string{"pdp.yaml", "pdp.yml", "pdp.json"} {
		if path := filepath.Join(packRoot, name, file); fileExists(path) {
			matches = append(matches, path)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("pack %s needs exactly one pdp.yaml or pdp.json, found %v", name, matches)
	}
	return matches[0]
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// These packs need a Workload API, systemd, an interception CA or a cluster to
// serve, so this checks what can be checked offline: they load, and each
// documented explain input gets the decision its README states.
func TestDeploymentPacksValidate(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", "/run/credentials/pdp.service")
	for _, name := range []string{"github-spiffe", "systemd", "egress", "subscription", "kubernetes"} {
		if err := run([]string{"validate", "--config", packConfig(t, name)}, io.Discard, io.Discard); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for input, want := range map[string]bool{
		"github-spiffe/explain/approved-workload.json":         true,
		"github-spiffe/explain/neighbor-workload.json":         false,
		"egress/explain/read-package.yaml":                     true,
		"egress/explain/database-tunnel.yaml":                  true,
		"egress/explain/post-to-read-only-host.yaml":           false,
		"egress/explain/resolves-to-metadata.yaml":             false,
		"subscription/explain/granted-account.json":            true,
		"subscription/explain/other-accounts-placeholder.json": false,
		"subscription/explain/no-placeholder.json":             false,
		"kubernetes/explain/spiffe-workload.json":              true,
		"kubernetes/explain/steered-read.json":                 true,
		"kubernetes/explain/steered-credentialed-host.json":    false,
	} {
		var out bytes.Buffer
		pack, _, _ := strings.Cut(input, "/")
		if err := run([]string{"explain", "--config", packConfig(t, pack), "--input", filepath.Join(packRoot, input)}, &out, io.Discard); err != nil {
			t.Fatal(err)
		}
		var decision struct {
			Allow bool `json:"allow"`
		}
		if err := json.Unmarshal(out.Bytes(), &decision); err != nil || decision.Allow != want {
			t.Fatalf("%s: allow=%v want=%v: %s", input, decision.Allow, want, out.String())
		}
	}
}
