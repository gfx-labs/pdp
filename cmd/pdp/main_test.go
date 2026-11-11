//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/gfx-labs/pdp/pkg/config"
	"github.com/gfx-labs/pdp/pkg/credential"
	"github.com/gfx-labs/pdp/pkg/schema"
)

func TestCLISchemaDiff(t *testing.T) {
	before := "../../pkg/schema/testdata/github-rest.json"
	data, err := os.ReadFile(before)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err = json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	operation := document["paths"].(map[string]any)["/repos/{owner}/{repo}"].(map[string]any)
	operation["post"] = operation["get"]
	delete(operation, "get")
	data, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	after := filepath.Join(t.TempDir(), "changed.json")
	if err = os.WriteFile(after, data, 0600); err != nil {
		t.Fatal(err)
	}
	var out, errout bytes.Buffer
	if err = run([]string{"schema", "diff", "--protocol", "rest", before, after}, &out, &errout); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Changed    []string `json:"changed"`
		Operations []struct {
			Before schema.Operation `json:"before"`
			After  schema.Operation `json:"after"`
		} `json:"changed_operations"`
	}
	if err = json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Changed) != 1 || result.Changed[0] != "repos/get" || len(result.Operations) != 1 {
		t.Fatalf("changed provider operation missing from CLI output: %s", out.String())
	}
	change := result.Operations[0]
	if change.Before.Method != "GET" || change.After.Method != "POST" || len(change.Before.Contract) == 0 || len(change.After.Contract) == 0 {
		t.Fatalf("before/after request contracts missing: %s", out.String())
	}
}

// This child runs the real CLI with the race instrumentation of the test binary.
func TestCLIProcess(t *testing.T) {
	if os.Getenv("PDP_TEST_PROCESS") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			if os.Getenv("PDP_TEST_ACTIVATED") == "1" {
				os.Setenv("LISTEN_PID", fmt.Sprint(os.Getpid()))
			}
			if err := run(os.Args[i+1:], os.Stdout, os.Stderr); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			os.Exit(0)
		}
	}
	os.Exit(2)
}

// Owns CLI transport/lifecycle integration, not the external provider's API.
// It proves authorization precedes credentials and live reload revokes a warm
// cache on the actual Unix server, including caller-forged identity headers.
// The policy is a real Rego file, and revocation rewrites that file.
func TestCLISocketReload(t *testing.T) {
	for _, activated := range []bool{false, true} {
		t.Run(fmt.Sprintf("activated=%t", activated), func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			socket := filepath.Join(dir, "pdp.sock")
			secret := filepath.Join(dir, "token")
			if err := os.WriteFile(secret, []byte("local-transport-test-token"), 0600); err != nil {
				t.Fatal(err)
			}
			var reached atomic.Int32
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer local-transport-test-token" || r.URL.Path != "/repos/approved/repo" || r.Header.Get("X-PDP-Identity") != "" {
					w.WriteHeader(500)
					return
				}
				reached.Add(1)
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"accepted":true}`)
			}))
			defer upstream.Close()
			ca := filepath.Join(dir, "ca.pem")
			if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			policyPath := filepath.Join(dir, "policy.rego")
			writePolicy := func(uid int) {
				t.Helper()
				source := fmt.Sprintf("package pdp.authz\n\nimport rego.v1\n\ndefault allow := false\n\nallow if {\n\tinput.identity.auth_method == \"unix\"\n\tinput.identity.uid == %d\n\tinput.provider == \"github\"\n\tinput.binding == \"local\"\n}\n", uid)
				if err := os.WriteFile(policyPath, []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
			}
			writePolicy(os.Getuid())
			cfg := config.Config{Version: config.Version, Revision: "initial", CAFile: ca,
				Transport:   config.Transport{UnixSocket: socket, SocketMode: "0600"},
				Routes:      []config.Route{{Provider: "github", Binding: "local", UpstreamURL: upstream.URL}},
				Credentials: credential.Config{Providers: map[string]credential.ProviderConfig{"github": {Script: "def acquire(request):\n    return static(secret(\"token\"))\n"}}, Bindings: map[string]credential.BindingConfig{"local": {Provider: "github", Secrets: map[string]credential.SecretSource{"token": {File: secret}}}}},
				Policy:      config.Policy{Modules: []string{"policy.rego"}}}
			path := filepath.Join(dir, "pdp.json")
			writeConfig := func() {
				t.Helper()
				b, err := json.Marshal(cfg)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(path, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			writeConfig()
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(exe, "-test.run=^TestCLIProcess$", "--", "serve", "--config", path)
			cmd.Env = append(os.Environ(), "PDP_TEST_PROCESS=1", "LISTEN_PID=", "LISTEN_FDS=", "LISTEN_FDNAMES=")
			var activation *net.UnixListener
			if activated {
				activation, err = net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
				if err != nil {
					t.Fatal(err)
				}
				defer activation.Close()
				file, err := activation.File()
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				cmd.ExtraFiles = []*os.File{file}
				cmd.Env = append(cmd.Env, "PDP_TEST_ACTIVATED=1", "LISTEN_FDS=1")
			}
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			stderr, err := cmd.StderrPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			defer func() {
				cmd.Process.Signal(syscall.SIGTERM)
				select {
				case err := <-done:
					if err != nil {
						t.Errorf("CLI exit: %v", err)
					}
				case <-time.After(5 * time.Second):
					cmd.Process.Kill()
					<-done
					t.Error("CLI shutdown timed out")
				}
			}()
			lines := make(chan string, 64)
			go func() {
				scanner := bufio.NewScanner(stderr)
				for scanner.Scan() {
					lines <- scanner.Text()
				}
				close(lines)
			}()
			ready := make(chan bool, 1)
			go func() {
				var status map[string]any
				ready <- json.NewDecoder(stdout).Decode(&status) == nil && status["state"] == "ready"
			}()
			select {
			case ok := <-ready:
				if !ok {
					var messages []string
					for line := range lines {
						messages = append(messages, line)
					}
					t.Fatalf("CLI failed before readiness: %s", strings.Join(messages, "\n"))
				}
			case <-time.After(10 * time.Second):
				t.Fatal("CLI readiness timeout")
			}
			transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			request := func(want int) {
				t.Helper()
				req, _ := http.NewRequest("GET", "http://pdp/upstreams/github/repos/approved/repo", nil)
				req.Header.Set("Authorization", "Bearer forged")
				req.Header.Set("X-PDP-Identity", "admin")
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode != want {
					t.Fatalf("HTTP %d, want %d: %s", resp.StatusCode, want, body)
				}
				if bytes.Contains(body, []byte("local-transport-test-token")) {
					t.Fatal("credential in response")
				}
			}
			var response bytes.Buffer
			if err := run([]string{"request", "--socket", socket, "--path", "/upstreams/github/repos/approved/repo"}, &response, io.Discard); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(response.String(), `"accepted":true`) {
				t.Fatalf("request CLI response: %s", response.String())
			}
			if err := os.Remove(secret); err != nil {
				t.Fatal(err)
			}
			request(200)
			waitEvent := func(event string) map[string]any {
				t.Helper()
				timer := time.NewTimer(5 * time.Second)
				defer timer.Stop()
				for {
					select {
					case line, ok := <-lines:
						if !ok {
							t.Fatal("CLI stderr closed")
						}
						var record map[string]any
						if json.Unmarshal([]byte(line), &record) == nil && record["event"] == event {
							return record
						}
					case <-timer.C:
						t.Fatalf("missing %s", event)
					}
				}
			}
			cfg.Revision = ""
			writeConfig()
			cmd.Process.Signal(syscall.SIGHUP)
			waitEvent("reload_rejected")
			request(200)
			// Revocation is a policy change: the Rego no longer names this UID.
			cfg.Revision = "revoked"
			writePolicy(os.Getuid() + 1)
			writeConfig()
			cmd.Process.Signal(syscall.SIGHUP)
			ack := waitEvent("reload_applied")
			if ack["revision"] != cfg.Revision {
				t.Fatalf("reload acknowledgement revision: %v", ack)
			}
			request(403)
			if reached.Load() != 3 {
				t.Fatalf("forbidden request reached upstream: %d calls", reached.Load())
			}
			if activated {
				if _, err := os.Stat(socket); err != nil {
					t.Fatalf("activated socket disappeared: %v", err)
				}
			}
		})
	}
}
