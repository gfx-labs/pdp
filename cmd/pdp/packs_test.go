//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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
	path   string
	body   string // file under the pack's requests directory
	status int
}

// Owns the claim that each checked-in pack is usable as shipped. It serves the
// pack's own policy.rego, schema and adapter on a real Unix socket against a
// local TLS provider, changing only deployment values: socket, secret paths,
// provider URLs and the allowed UID.
func TestPacksServeTheirRequests(t *testing.T) {
	const repo = "/upstreams/github/repos/APPROVED_OWNER/APPROVED_REPOSITORY"
	const other = "/upstreams/github/repos/UNAPPROVED_OWNER/APPROVED_REPOSITORY"
	const linear = "/upstreams/linear/graphql"
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
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: provider.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	document["ca_file"] = ca
	for _, entry := range document["routes"].([]any) {
		route := entry.(map[string]any)
		route["upstream_url"] = provider.URL
		if route["provider"] == "linear" {
			route["upstream_url"] = provider.URL + "/graphql"
		}
	}
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
	g, err := gateway.New(s, gatewayOptions(loaded))
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
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	for _, want := range requests {
		var body []byte
		if want.body != "" {
			if body, err = os.ReadFile(filepath.Join(dir, "requests", want.body)); err != nil {
				t.Fatal(err)
			}
		}
		request, err := http.NewRequest(want.method, "http://pdp"+want.path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		exchangesBefore, forwardedBefore := exchanges.Load(), forwarded.Load()
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(response.Body)
		response.Body.Close()
		label := fmt.Sprintf("%s %s %s", want.method, want.path, want.body)
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

// The SPIFFE and systemd packs need a Workload API and systemd to serve, so
// this checks what can be checked offline: they load, and the SPIFFE policy
// separates the named workload from a neighbor in the same trust domain.
func TestDeploymentPacksValidate(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", "/run/credentials/pdp.service")
	for _, name := range []string{"github-spiffe", "systemd"} {
		if err := run([]string{"validate", "--config", filepath.Join(packRoot, name, "pdp.json")}, io.Discard, io.Discard); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for input, want := range map[string]bool{"approved-workload.json": true, "neighbor-workload.json": false} {
		var out bytes.Buffer
		if err := run([]string{"explain", "--config", filepath.Join(packRoot, "github-spiffe", "pdp.json"), "--input", filepath.Join(packRoot, "github-spiffe", "explain", input)}, &out, io.Discard); err != nil {
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
