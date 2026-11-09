package credential_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gfx-labs/pdp/internal/credential"
	"github.com/gfx-labs/pdp/internal/credential/adapters"
)

func secretFile(t *testing.T, dir, name, value string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}
func manager(t *testing.T, c credential.Config) *credential.Manager {
	t.Helper()
	m, err := credential.New(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	return m
}
func tlsConfig(t *testing.T, script string, handler http.HandlerFunc) (credential.Config, *httptest.Server) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	dir := t.TempDir()
	secret := secretFile(t, dir, "secret", "fixture-client-secret")
	return credential.Config{RootCAs: roots, Providers: map[string]credential.ProviderConfig{"provider": {Script: script, Endpoints: map[string]string{"token": server.URL + "/token"}}}, Bindings: map[string]credential.BindingConfig{"binding": {Provider: "provider", Secrets: map[string]credential.SecretSource{"client_secret": {File: secret}}, Parameters: map[string]string{"client_id": "fixture-client"}, Scopes: []string{"read", "write"}}}}, server
}
func request() credential.Request {
	return credential.Request{Provider: "provider", Binding: "binding", Scopes: []string{"write", "read"}}
}
func authorization(t *testing.T, r credential.Result) string {
	t.Helper()
	headers := make(http.Header)
	if err := r.Apply(headers); err != nil {
		t.Fatal(err)
	}
	return headers.Get("Authorization")
}
func requireCode(t *testing.T, err error, code credential.Code) {
	t.Helper()
	var safe *credential.Error
	if !errors.As(err, &safe) || safe.Code != code {
		t.Fatalf("expected error code %s", code)
	}
}

// Protects mounted-file reread/invalidation, canonical cache keys and safe public
// formatting through the actual checked-in static adapter and injection API.
func TestStaticLifecycleAndRedaction(t *testing.T) {
	dir := t.TempDir()
	path := secretFile(t, dir, "token", "fixture-first-token\n")
	c := credential.Config{CredentialsDirectory: dir, Providers: map[string]credential.ProviderConfig{"provider": {Script: adapters.Static}}, Bindings: map[string]credential.BindingConfig{"binding": {Provider: "provider", Secrets: map[string]credential.SecretSource{"token": {SystemdCredential: "token"}}, Scopes: []string{"read", "write"}}}}
	m := manager(t, c)
	if err := m.Validate(request()); err != nil {
		t.Fatal(err)
	}
	got, err := m.Get(context.Background(), request())
	if err != nil {
		t.Fatal(err)
	}
	if authorization(t, got) != "Bearer fixture-first-token" {
		t.Fatal("wrong injected credential")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		if strings.Contains(fmt.Sprintf(format, got), "fixture-first-token") {
			t.Fatal("credential leaked through formatting")
		}
	}
	raw, err := json.Marshal(got)
	if err != nil || strings.Contains(string(raw), "fixture-first-token") {
		t.Fatal("credential leaked through JSON")
	}
	if err := os.WriteFile(path, []byte("fixture-second-token"), 0600); err != nil {
		t.Fatal(err)
	}
	canonical := request()
	canonical.Scopes = []string{"read", "write"}
	cached, err := m.Get(context.Background(), canonical)
	if err != nil {
		t.Fatal(err)
	}
	if authorization(t, cached) != "Bearer fixture-first-token" {
		t.Fatal("scope reordering changed cache identity")
	}
	m.Invalidate(canonical)
	updated, err := m.Get(context.Background(), request())
	if err != nil {
		t.Fatal(err)
	}
	if authorization(t, updated) != "Bearer fixture-second-token" {
		t.Fatal("invalidation did not reread mounted secret")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	m.Invalidate(request())
	_, err = m.Get(context.Background(), request())
	requireCode(t, err, credential.CodeUnavailable)
	if strings.Contains(err.Error(), path) {
		t.Fatal("secret path leaked in error")
	}
	m.Close()
	_, err = m.Get(context.Background(), request())
	requireCode(t, err, credential.CodeUnavailable)
}

// Protects native form serialization, TLS trust, keyed singleflight, invalidation
// and fail-closed acquisition through a real HTTPS token endpoint.
func TestOAuthSingleflightAndFailureClosed(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var count atomic.Int32
	var fail atomic.Bool
	c, _ := tlsConfig(t, adapters.OAuthClientCredentials, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" || r.Method != "POST" {
			t.Error("wrong fixed token destination")
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_id") != "fixture-client" || r.Form.Get("client_secret") != "fixture-client-secret" || r.Form.Get("scope") != "read write" {
			t.Error("wrong OAuth form")
		}
		if count.Add(1) == 1 {
			close(entered)
			<-release
		}
		if fail.Load() {
			w.WriteHeader(401)
			_, _ = io.WriteString(w, "fixture-client-secret private provider error")
			return
		}
		_, _ = io.WriteString(w, `{"access_token":"fixture-access","token_type":"Bearer","expires_in":3600,"scope":"read write"}`)
	})
	m := manager(t, c)
	var releaseOnce sync.Once
	releaseEndpoint := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseEndpoint)
	var wg sync.WaitGroup
	errs := make(chan error, 24)
	wg.Add(1)
	go func() { defer wg.Done(); _, err := m.Get(context.Background(), request()); errs <- err }()
	<-entered
	initial := m.Stats()
	if initial.InFlight != 1 || initial.Acquisitions != 1 || initial.Misses != 1 || initial.Hits != 0 || initial.Failures != 0 {
		t.Fatal("initial acquisition metrics are inconsistent")
	}
	joinContext, cancelJoin := context.WithTimeout(context.Background(), 10*time.Millisecond)
	_, joinErr := m.Get(joinContext, request())
	cancelJoin()
	requireCode(t, joinErr, credential.CodeCanceled)
	if stats := m.Stats(); stats.Coalesced != 1 || stats.InFlight != 1 {
		t.Fatal("coalesced cancellation was not counted without starting another acquisition")
	}
	for range 20 {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := m.Get(context.Background(), request()); errs <- err }()
	}
	releaseEndpoint()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if count.Load() != 1 {
		t.Fatal("duplicate token exchange for identical concurrent scope key")
	}
	completed := m.Stats()
	if completed.Acquisitions != 1 || completed.InFlight != 0 || completed.Failures != 0 || completed.Misses != completed.Coalesced+1 || completed.Hits+completed.Coalesced != 21 || completed.AcquisitionNanoseconds == 0 {
		t.Fatal("completed credential metrics are inconsistent")
	}
	fail.Store(true)
	m.Invalidate(request())
	_, err := m.Get(context.Background(), request())
	requireCode(t, err, credential.CodeUnavailable)
	if strings.Contains(err.Error(), "fixture") {
		t.Fatal("provider response leaked")
	}
	if count.Load() != 2 {
		t.Fatal("invalidation did not force one fresh exchange")
	}
	failed := m.Stats()
	if failed.Acquisitions != 2 || failed.Failures != 1 || failed.InFlight != 0 || failed.AcquisitionNanoseconds <= completed.AcquisitionNanoseconds {
		t.Fatal("failed acquisition metrics are inconsistent")
	}
}

// These contracts are independent transport escape, resource bound and script
// isolation failures. No arbitrary RoundTripper is injected into production.
func TestRuntimeAndTransportBounds(t *testing.T) {
	t.Run("redirect", func(t *testing.T) {
		var redirected atomic.Int32
		sink := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
		defer sink.Close()
		c, _ := tlsConfig(t, adapters.OAuthClientCredentials, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, sink.URL, http.StatusTemporaryRedirect)
		})
		m := manager(t, c)
		_, err := m.Get(context.Background(), request())
		requireCode(t, err, credential.CodeUnavailable)
		if redirected.Load() != 0 {
			t.Fatal("followed credential redirect")
		}
	})
	t.Run("untrusted TLS", func(t *testing.T) {
		var hits atomic.Int32
		c, _ := tlsConfig(t, adapters.OAuthClientCredentials, func(w http.ResponseWriter, r *http.Request) { hits.Add(1) })
		c.RootCAs = x509.NewCertPool()
		m := manager(t, c)
		_, err := m.Get(context.Background(), request())
		requireCode(t, err, credential.CodeUnavailable)
		if hits.Load() != 0 {
			t.Fatal("untrusted TLS reached HTTP handler")
		}
	})
	t.Run("response bound", func(t *testing.T) {
		c, _ := tlsConfig(t, adapters.OAuthClientCredentials, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, strings.Repeat("x", 2048)) })
		c.Limits.MaxHTTPResponseBytes = 1024
		m := manager(t, c)
		_, err := m.Get(context.Background(), request())
		requireCode(t, err, credential.CodeLimited)
	})
	t.Run("deadline and concurrency", func(t *testing.T) {
		entered := make(chan struct{})
		c, _ := tlsConfig(t, adapters.OAuthClientCredentials, func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			close(entered)
			<-r.Context().Done()
		})
		c.Limits.Timeout = 200 * time.Millisecond
		c.Limits.MaxConcurrent = 1
		b := c.Bindings["binding"]
		c.Bindings["other"] = b
		m := manager(t, c)
		done := make(chan error, 1)
		go func() { _, err := m.Get(context.Background(), request()); done <- err }()
		<-entered
		other := request()
		other.Binding = "other"
		_, err := m.Get(context.Background(), other)
		requireCode(t, err, credential.CodeLimited)
		requireCode(t, <-done, credential.CodeCanceled)
	})
	for _, tc := range []struct {
		name, script string
		code         credential.Code
	}{
		{"instructions", "def acquire(request):\n    for i in range(1000000):\n        x = i * i\n    return None\n", credential.CodeLimited},
		{"typed result", "def acquire(request):\n    return {\"token\": \"not-an-opaque-result\"}\n", credential.CodeInvalid},
		{"secret opaque", "def acquire(request):\n    return static(str(secret(\"token\")))\n", credential.CodeInvalid},
		{"error sanitized", "def acquire(request):\n    fail(\"fixture-sensitive-error\")\n", credential.CodeUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := credential.Config{Limits: credential.Limits{MaxSteps: 1000}, Providers: map[string]credential.ProviderConfig{"provider": {Script: tc.script}}, Bindings: map[string]credential.BindingConfig{"binding": {Provider: "provider", Secrets: map[string]credential.SecretSource{"token": {File: filepath.Join(t.TempDir(), "not-read")}}, Scopes: []string{"read", "write"}}}}
			m := manager(t, c)
			_, err := m.Get(context.Background(), request())
			requireCode(t, err, tc.code)
			if strings.Contains(err.Error(), "fixture-sensitive-error") {
				t.Fatal("script traceback leaked")
			}
		})
	}
}

func TestTokenExchangesUseFreshHTTP1WithoutRefreshReplay(t *testing.T) {
	dir := privateDir(t)
	statePath := secretFile(t, dir, "state.json", `{"refresh_token":"before","scopes":["read","write"]}`)
	var mu sync.Mutex
	addresses := map[string]bool{}
	count := 0
	c, _ := tlsConfig(t, adapters.OAuthRefresh, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		mu.Lock()
		count++
		attempt := count
		alreadyUsed := addresses[r.RemoteAddr]
		addresses[r.RemoteAddr] = true
		mu.Unlock()
		if r.TLS == nil {
			t.Error("token exchange was not TLS")
			w.WriteHeader(500)
			return
		}
		if r.ProtoMajor != 1 || (r.TLS.NegotiatedProtocol != "" && r.TLS.NegotiatedProtocol != "http/1.1") || !r.Close || alreadyUsed {
			t.Errorf("token transport proto=%s ALPN=%q close=%t reused=%t", r.Proto, r.TLS.NegotiatedProtocol, r.Close, alreadyUsed)
		}
		if attempt == 1 {
			_, _ = io.WriteString(w, `{"access_token":"access","refresh_token":"after","token_type":"Bearer","expires_in":3600,"scope":"read write"}`)
			return
		}
		// Simulate a provider consuming a rotating grant then losing its reply.
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Error("token exchange did not use HTTP/1")
			w.WriteHeader(500)
			return
		}
		connection, _, err := hijacker.Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = connection.Close()
	})
	b := c.Bindings["binding"]
	b.StateFile = statePath
	c.Bindings["binding"] = b
	m := manager(t, c)
	if _, err := m.Get(context.Background(), request()); err != nil {
		t.Fatal(err)
	}
	m.Invalidate(request())
	_, err := m.Get(context.Background(), request())
	requireCode(t, err, credential.CodeUnavailable)
	_, err = m.Get(context.Background(), request())
	requireCode(t, err, credential.CodePersistence)
	restarted := manager(t, c)
	_, err = restarted.Get(context.Background(), request())
	requireCode(t, err, credential.CodePersistence)
	mu.Lock()
	defer mu.Unlock()
	if count != 2 || len(addresses) != 2 {
		t.Fatal("unknown rotating exchange was replayed or connection was reused")
	}
}

// Runs separate managers sharing an actual state file and advisory lock. The
// endpoint rejects replayed refresh tokens, so unsafe rotation cannot pass.
func TestRefreshSerializedAndDurable(t *testing.T) {
	dir := privateDir(t)
	statePath := secretFile(t, dir, "state.json", `{"refresh_token":"refresh-0","scopes":["read","write"]}`)
	var mu sync.Mutex
	next := 0
	c, _ := tlsConfig(t, adapters.LinearRefresh, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		mu.Lock()
		defer mu.Unlock()
		if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != fmt.Sprintf("refresh-%d", next) {
			t.Error("replayed or unpersisted rotating refresh token")
			w.WriteHeader(400)
			return
		}
		next++
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": fmt.Sprintf("access-%d", next), "refresh_token": fmt.Sprintf("refresh-%d", next), "expires_in": 3600, "token_type": "Bearer", "scope": "read write"})
	})
	b := c.Bindings["binding"]
	b.StateFile = statePath
	b.LinearActor = "app"
	c.Bindings["binding"] = b
	managers := []*credential.Manager{manager(t, c), manager(t, c)}
	var wg sync.WaitGroup
	for _, m := range managers {
		wg.Add(1)
		go func(m *credential.Manager) {
			defer wg.Done()
			r, err := m.Get(context.Background(), request())
			if err != nil {
				t.Error(err)
				return
			}
			if !strings.HasPrefix(authorization(t, r), "Bearer access-") {
				t.Error("wrong refreshed access token")
			}
		}(m)
	}
	wg.Wait()
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var persisted struct {
		AccessToken  string    `json:"access_token"`
		RefreshToken string    `json:"refresh_token"`
		ExpiresAt    time.Time `json:"expires_at"`
	}
	if json.Unmarshal(raw, &persisted) != nil || persisted.AccessToken != "access-2" || persisted.RefreshToken != "refresh-2" || persisted.ExpiresAt.IsZero() {
		t.Fatal("complete replacement pair was not persisted before return")
	}
	info, err := os.Stat(statePath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("rotation state permissions widened")
	}
	m := manager(t, c)
	if _, err := m.Get(context.Background(), request()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if next != 3 {
		t.Fatal("restart did not use last durable refresh token")
	}
}

// The real provider endpoint makes persistence fail only after accepting the
// refresh. This protects against returning or later caching an uncommitted pair.
func TestRotationPersistenceFailureNeverReleasesCredential(t *testing.T) {
	dir := privateDir(t)
	statePath := secretFile(t, dir, "state.json", `{"refresh_token":"refresh-before","scopes":["read","write"]}`)
	var count atomic.Int32
	c, _ := tlsConfig(t, adapters.OAuthRefresh, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		count.Add(1)
		if err := os.Remove(statePath); err != nil {
			t.Error(err)
		}
		if err := os.Mkdir(statePath, 0700); err != nil {
			t.Error(err)
		}
		_, _ = io.WriteString(w, `{"access_token":"uncommitted-access","refresh_token":"uncommitted-refresh","token_type":"Bearer","expires_in":3600,"scope":"read write"}`)
	})
	b := c.Bindings["binding"]
	b.StateFile = statePath
	c.Bindings["binding"] = b
	m := manager(t, c)
	result, err := m.Get(context.Background(), request())
	requireCode(t, err, credential.CodePersistence)
	if result.Apply(make(http.Header)) == nil {
		t.Fatal("uncommitted access credential escaped")
	}
	_, err = m.Get(context.Background(), request())
	requireCode(t, err, credential.CodePersistence)
	if count.Load() != 1 {
		t.Fatal("poisoned binding retried uncertain refresh")
	}
}

func TestRotationUnusableResponseRemainsFailClosedAfterRestart(t *testing.T) {
	dir := privateDir(t)
	statePath := secretFile(t, dir, "state.json", `{"refresh_token":"before","scopes":["read","write"]}`)
	var count atomic.Int32
	c, _ := tlsConfig(t, adapters.LinearRefresh, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		count.Add(1)
		raw, err := os.ReadFile(statePath)
		var intent struct {
			Pending bool `json:"recovery_required"`
		}
		if err != nil || json.Unmarshal(raw, &intent) != nil || !intent.Pending {
			t.Error("refresh effect preceded durable intent")
		}
		_, _ = io.WriteString(w, `{"access_token":"too-short","refresh_token":"replacement","token_type":"Bearer","expires_in":10,"scope":"read write"}`)
	})
	b := c.Bindings["binding"]
	b.StateFile = statePath
	b.LinearActor = "app"
	c.Bindings["binding"] = b
	m := manager(t, c)
	result, err := m.Get(context.Background(), request())
	requireCode(t, err, credential.CodeUnavailable)
	if result.Apply(make(http.Header)) == nil {
		t.Fatal("unusable credential escaped")
	}
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var persisted struct {
		RefreshToken string `json:"refresh_token"`
		Pending      bool   `json:"recovery_required"`
	}
	if json.Unmarshal(raw, &persisted) != nil || persisted.RefreshToken != "replacement" || !persisted.Pending {
		t.Fatal("rotated replacement was discarded on access-token validation failure")
	}
	m.Close()
	restarted := manager(t, c)
	_, err = restarted.Get(context.Background(), request())
	requireCode(t, err, credential.CodePersistence)
	if count.Load() != 1 {
		t.Fatal("restart replayed an uncertain rotating grant")
	}
}

func TestRotationProcessCrashFailsClosed(t *testing.T) {
	if os.Getenv("PDP_CREDENTIAL_CRASH_CHILD") == "1" {
		raw, err := os.ReadFile(os.Getenv("PDP_CREDENTIAL_TEST_CONFIG"))
		if err != nil {
			t.Fatal(err)
		}
		var c credential.Config
		if json.Unmarshal(raw, &c) != nil {
			t.Fatal("invalid child config")
		}
		cert, err := os.ReadFile(os.Getenv("PDP_CREDENTIAL_TEST_CA"))
		if err != nil {
			t.Fatal(err)
		}
		c.RootCAs = x509.NewCertPool()
		if !c.RootCAs.AppendCertsFromPEM(cert) {
			t.Fatal("invalid child CA")
		}
		m := manager(t, c)
		_, err = m.Get(context.Background(), request())
		t.Fatalf("interrupted refresh unexpectedly returned: %v", err)
		return
	}
	dir := privateDir(t)
	statePath := secretFile(t, dir, "state.json", `{"refresh_token":"before-crash","scopes":["read","write"]}`)
	entered := make(chan struct{})
	var count atomic.Int32
	c, server := tlsConfig(t, adapters.OAuthRefresh, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if count.Add(1) == 1 {
			close(entered)
		}
		<-r.Context().Done()
	})
	b := c.Bindings["binding"]
	b.StateFile = statePath
	c.Bindings["binding"] = b
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	configPath := secretFile(t, dir, "config.json", string(raw))
	certPath := secretFile(t, dir, "ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})))
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(executable, "-test.run=^TestRotationProcessCrashFailsClosed$")
	child.Env = append(os.Environ(), "PDP_CREDENTIAL_CRASH_CHILD=1", "PDP_CREDENTIAL_TEST_CONFIG="+configPath, "PDP_CREDENTIAL_TEST_CA="+certPath)
	var output strings.Builder
	child.Stdout = &output
	child.Stderr = &output
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	t.Cleanup(func() { _ = child.Process.Kill() })
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("child exited before refresh: %v: %s", err, output.String())
	case <-time.After(5 * time.Second):
		_ = child.Process.Kill()
		<-done
		t.Fatal("child did not reach token endpoint")
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	<-done
	restarted := manager(t, c)
	_, err = restarted.Get(context.Background(), request())
	requireCode(t, err, credential.CodePersistence)
	if count.Load() != 1 {
		t.Fatal("process restart replayed refresh with unknown outcome")
	}
}

func TestResultDetectsCredentialReflection(t *testing.T) {
	for _, kind := range []string{"bearer", "basic", "header"} {
		t.Run(kind, func(t *testing.T) {
			path := secretFile(t, t.TempDir(), "token", "fixture<private>/token")
			script := fmt.Sprintf("def acquire(request):\n    return static(secret(\"token\"), kind=%q, username=\"user\", header_name=\"X-API-Key\")\n", kind)
			c := credential.Config{Providers: map[string]credential.ProviderConfig{"provider": {Script: script}}, Bindings: map[string]credential.BindingConfig{"binding": {Provider: "provider", Secrets: map[string]credential.SecretSource{"token": {File: path}}, Scopes: []string{"read", "write"}}}}
			m := manager(t, c)
			result, err := m.Get(context.Background(), request())
			if err != nil {
				t.Fatal(err)
			}
			headers := make(http.Header)
			if err := result.Apply(headers); err != nil {
				t.Fatal(err)
			}
			applied := headers.Get("Authorization")
			if kind == "header" {
				applied = headers.Get("X-API-Key")
			}
			if !result.ContainsSecret([]byte(applied)) || !result.ContainsSecret([]byte("fixture<private>/token")) {
				t.Fatal("raw credential reflection was not detected")
			}
			if result.ContainsSecret([]byte(`{"safe":"ordinary response"}`)) {
				t.Fatal("ordinary response was rejected")
			}
			encoded, _ := json.Marshal(map[string]string{"echo": applied})
			if !result.ContainsSecret(encoded) {
				t.Fatal("JSON escaped credential reflection was not detected")
			}
			// Duplicate keys and alternate JSON escapes must not hide a secret.
			if !result.ContainsSecret([]byte(`{"echo":"fixture\u003cprivate\u003e\/token","echo":"safe"}`)) {
				t.Fatal("duplicate JSON key hid credential material")
			}
		})
	}
}

// This verifies the broker's actual request restrictions and signing at its
// HTTPS boundary, not the RSA dependency's implementation.
func TestGitHubAppRestrictedExchange(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := secretFile(t, t.TempDir(), "key.pem", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})))
	c, _ := tlsConfig(t, adapters.GitHubApp, func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Error("missing app JWT")
			w.WriteHeader(400)
			return
		}
		signature, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Error("invalid JWT signature encoding")
		}
		hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, hash[:], signature) != nil {
			t.Error("app JWT not signed by configured key")
		}
		claimsRaw, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var claims struct {
			Issuer string `json:"iss"`
			IAT    int64  `json:"iat"`
			EXP    int64  `json:"exp"`
		}
		_ = json.Unmarshal(claimsRaw, &claims)
		if claims.Issuer != "123" || claims.IAT > time.Now().Unix() || claims.EXP > time.Now().Add(10*time.Minute).Unix() {
			t.Error("wrong app JWT claims")
		}
		var payload struct {
			RepositoryIDs []int64           `json:"repository_ids"`
			Permissions   map[string]string `json:"permissions"`
		}
		if json.NewDecoder(r.Body).Decode(&payload) != nil || len(payload.RepositoryIDs) != 1 || payload.RepositoryIDs[0] != 42 || payload.Permissions["contents"] != "read" || len(payload.Permissions) != 1 {
			t.Error("installation exchange widened authority")
		}
		if r.Header.Get("X-GitHub-Api-Version") == "" {
			t.Error("missing GitHub API version")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "fixture-installation", "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339), "permissions": map[string]string{"contents": "read", "metadata": "read"}, "repositories": []map[string]int{{"id": 42}}})
	})
	b := c.Bindings["binding"]
	b.Secrets = map[string]credential.SecretSource{"private_key": {File: keyPath}}
	b.GitHub = &credential.GitHubConfig{AppID: "123", RepositoryIDs: []int64{42}, Permissions: map[string]string{"contents": "read"}}
	c.Bindings["binding"] = b
	m := manager(t, c)
	result, err := m.Get(context.Background(), request())
	if err != nil {
		t.Fatal(err)
	}
	if authorization(t, result) != "Bearer fixture-installation" {
		t.Fatal("wrong installation token injection")
	}
}

func TestLinearClientCredentialsExplicitActorAndScopes(t *testing.T) {
	var count atomic.Int32
	c, _ := tlsConfig(t, adapters.LinearClientCredentials, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		count.Add(1)
		if r.Form.Get("scope") != "read,write" || r.Form.Get("grant_type") != "client_credentials" || r.Form.Has("actor") {
			t.Error("Linear client credentials did not follow documented app-actor grant")
		}
		_, _ = io.WriteString(w, `{"access_token":"fixture-linear","token_type":"Bearer","expires_in":2591999,"scope":"read write"}`)
	})
	b := c.Bindings["binding"]
	b.LinearActor = "user"
	c.Bindings["binding"] = b
	m := manager(t, c)
	_, err := m.Get(context.Background(), request())
	requireCode(t, err, credential.CodeInvalid)
	if count.Load() != 0 {
		t.Fatal("unsupported Linear client credentials user actor reached provider")
	}
	b.LinearActor = "app"
	c.Bindings["binding"] = b
	m = manager(t, c)
	result, err := m.Get(context.Background(), request())
	if err != nil {
		t.Fatal(err)
	}
	if authorization(t, result) != "Bearer fixture-linear" {
		t.Fatal("wrong Linear credential")
	}
	subset := request()
	subset.Scopes = []string{"read"}
	_, err = m.Get(context.Background(), subset)
	requireCode(t, err, credential.CodeInvalid)
	if count.Load() != 1 {
		t.Fatal("scope-changing Linear issuance reached provider")
	}
}
