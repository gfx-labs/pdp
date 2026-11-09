// pdpbench measures a real PDP subprocess against an isolated local TLS upstream.
// It does not measure provider-network or SPIRE overhead.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gfx-labs/pdp/internal/config"
	"github.com/gfx-labs/pdp/internal/credential"
	"github.com/gfx-labs/pdp/internal/policy"
)

type usage struct {
	RSSKiB int64
	Ticks  uint64
}

func processUsage(pid int) (usage, error) {
	var u usage
	status, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return u, err
	}
	scan := bufio.NewScanner(status)
	for scan.Scan() {
		f := strings.Fields(scan.Text())
		if len(f) >= 2 && f[0] == "VmRSS:" {
			u.RSSKiB, err = strconv.ParseInt(f[1], 10, 64)
		}
	}
	status.Close()
	if err != nil {
		return u, err
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return u, err
	}
	end := strings.LastIndexByte(string(stat), ')')
	if end < 0 {
		return u, errors.New("invalid process statistics")
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 13 {
		return u, errors.New("incomplete process statistics")
	}
	user, e1 := strconv.ParseUint(fields[11], 10, 64)
	system, e2 := strconv.ParseUint(fields[12], 10, 64)
	if e1 != nil || e2 != nil {
		return u, errors.New("invalid CPU statistics")
	}
	u.Ticks = user + system
	return u, scan.Err()
}

func milliseconds(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
func percentile(sorted []time.Duration, percent int) float64 {
	if len(sorted) == 0 {
		return 0
	}
	i := (len(sorted)*percent+99)/100 - 1
	if i < 0 {
		i = 0
	}
	return milliseconds(sorted[i])
}

func run() error {
	binary := flag.String("pdp", "./bin/pdp", "built PDP binary")
	n := flag.Int("requests", 500, "number of warm requests")
	concurrency := flag.Int("concurrency", 4, "concurrent clients")
	idle := flag.Duration("idle", time.Second, "idle CPU observation interval")
	flag.Parse()
	if *n < 1 || *n > 100000 || *concurrency < 1 || *concurrency > 32 || *idle < 100*time.Millisecond || *idle > time.Minute {
		return errors.New("invalid benchmark limits")
	}
	bin, err := filepath.Abs(*binary)
	if err != nil {
		return err
	}
	ticksRaw, err := exec.Command("getconf", "CLK_TCK").Output()
	if err != nil {
		return errors.New("cannot determine Linux CPU clock ticks")
	}
	ticks, err := strconv.ParseFloat(strings.TrimSpace(string(ticksRaw)), 64)
	if err != nil || ticks <= 0 {
		return errors.New("invalid CPU tick rate")
	}
	dir, err := os.MkdirTemp("", "pdpbench-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	token := hex.EncodeToString(random[:])
	clientSecret := "local-benchmark-only-" + token
	var tokenCalls, upstreamCalls atomic.Uint64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/oauth" {
			if r.Method != "POST" || r.ParseForm() != nil || r.Form.Get("client_secret") != clientSecret || r.Form.Get("grant_type") != "client_credentials" {
				w.WriteHeader(403)
				return
			}
			tokenCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path != "/repos/test/repo" || r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(403)
			return
		}
		upstreamCalls.Add(1)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}), 0600); err != nil {
		return err
	}
	secret := filepath.Join(dir, "client-secret")
	if err := os.WriteFile(secret, []byte(clientSecret), 0600); err != nil {
		return err
	}
	socket := filepath.Join(dir, "pdp.sock")
	credentials := credential.Config{
		Providers: map[string]credential.ProviderConfig{"github": {Script: "def acquire(request):\n    return oauth_client_credentials(endpoint=\"token\", client_id=\"benchmark\", client_secret=secret(\"client_secret\"))\n", Endpoints: map[string]string{"token": upstream.URL + "/oauth"}}},
		Bindings:  map[string]credential.BindingConfig{"benchmark": {Provider: "github", Secrets: map[string]credential.SecretSource{"client_secret": {File: secret}}}},
	}
	c := config.Config{Version: config.Version, Revision: "benchmark-v1", CAFile: ca,
		Transport: config.Transport{UnixSocket: socket, SocketMode: "0600"}, Identities: map[uint32]string{uint32(os.Getuid()): "local:benchmark"},
		Routes: []config.Route{{Provider: "github", Binding: "benchmark", UpstreamURL: upstream.URL}}, Credentials: credentials,
		Policy: policy.Config{Revision: "benchmark-v1", Grants: []policy.Grant{{ID: "benchmark-full", Mode: policy.Full, Scope: policy.Scope{Identities: []string{"local:benchmark"}, Providers: []string{"github"}, Bindings: []string{"benchmark"}}}}},
	}
	encoded, err := json.Marshal(c)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "pdp.json")
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "serve", "-config", path)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	// Daemon audit output is excluded from benchmark output and cannot print tokens.
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return err
	}
	finished := make(chan error, 1)
	go func() { finished <- cmd.Wait() }()
	defer func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-finished
		}
	}()
	ready := make(chan bool, 1)
	go func() {
		var line map[string]any
		err := json.NewDecoder(stdout).Decode(&line)
		ready <- err == nil && line["state"] == "ready"
	}()
	select {
	case ok := <-ready:
		if !ok {
			return errors.New("daemon failed before readiness")
		}
	case <-time.After(15 * time.Second):
		return errors.New("daemon readiness timed out")
	}
	startIdle, err := processUsage(cmd.Process.Pid)
	if err != nil {
		return err
	}
	idleStart := time.Now()
	time.Sleep(*idle)
	endIdle, err := processUsage(cmd.Process.Pid)
	if err != nil {
		return err
	}
	idleElapsed := time.Since(idleStart)
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request := func() (time.Duration, error) {
		start := time.Now()
		resp, err := client.Get("http://pdp/upstreams/github/repos/test/repo")
		if err != nil {
			return 0, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 || string(body) != `{"ok":true}` {
			return 0, errors.New("gateway request failed")
		}
		return time.Since(start), nil
	}
	cold, err := request()
	if err != nil {
		return err
	}
	var peak atomic.Int64
	peak.Store(endIdle.RSSKiB)
	stopSample := make(chan struct{})
	var sampler sync.WaitGroup
	sampler.Add(1)
	go func() {
		defer sampler.Done()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopSample:
				return
			case <-ticker.C:
				if u, e := processUsage(cmd.Process.Pid); e == nil {
					for old := peak.Load(); u.RSSKiB > old; old = peak.Load() {
						if peak.CompareAndSwap(old, u.RSSKiB) {
							break
						}
					}
				}
			}
		}
	}()
	defer func() { close(stopSample); sampler.Wait() }()
	before, err := processUsage(cmd.Process.Pid)
	if err != nil {
		return err
	}
	durations := make([]time.Duration, *n)
	var index atomic.Int64
	var failures atomic.Int64
	var clients sync.WaitGroup
	start := time.Now()
	for i := 0; i < *concurrency; i++ {
		clients.Add(1)
		go func() {
			defer clients.Done()
			for {
				j := int(index.Add(1) - 1)
				if j >= *n {
					return
				}
				d, e := request()
				if e != nil {
					failures.Add(1)
				}
				durations[j] = d
			}
		}()
	}
	clients.Wait()
	elapsed := time.Since(start)
	after, err := processUsage(cmd.Process.Pid)
	if err != nil {
		return err
	}
	if failures.Load() != 0 {
		return fmt.Errorf("%d benchmark requests failed", failures.Load())
	}
	if tokenCalls.Load() != 1 || upstreamCalls.Load() != uint64(*n+1) {
		return errors.New("unexpected upstream or token request counts")
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	// Time the same native adapter path independently, without HTTP proxy latency.
	credentials.RootCAs = x509.NewCertPool()
	credentials.RootCAs.AddCert(upstream.Certificate())
	manager, err := credential.New(credentials)
	if err != nil {
		return err
	}
	defer manager.Close()
	lease := credential.Request{Provider: "github", Binding: "benchmark"}
	if _, err := manager.Get(ctx, lease); err != nil {
		return err
	}
	manager.Invalidate(lease)
	refreshStart := time.Now()
	if _, err := manager.Get(ctx, lease); err != nil {
		return err
	}
	refresh := time.Since(refreshStart)
	if tokenCalls.Load() != 3 {
		return errors.New("adapter invalidation did not cause exactly one reacquisition")
	}
	result := map[string]any{
		"scope":    "local Unix-authenticated daemon + embedded OPA + Starlark OAuth acquisition + loopback TLS upstream; no real provider or SPIRE",
		"requests": *n, "concurrency": *concurrency, "daemon_token_exchanges": 1,
		"total_local_token_exchanges":               tokenCalls.Load(),
		"local_client_credentials_reacquisition_ms": milliseconds(refresh),
		"idle_rss_kib":                              endIdle.RSSKiB, "active_sampled_peak_rss_kib": max(peak.Load(), after.RSSKiB),
		"idle_observation_ms": milliseconds(idleElapsed), "idle_cpu_ms": float64(endIdle.Ticks-startIdle.Ticks) * 1000 / ticks,
		"active_wall_ms": milliseconds(elapsed), "active_cpu_ms": float64(after.Ticks-before.Ticks) * 1000 / ticks,
		"cold_request_including_token_acquisition_ms": milliseconds(cold),
		"warm_request_p50_ms":                         percentile(durations, 50), "warm_request_p95_ms": percentile(durations, 95), "warm_request_p99_ms": percentile(durations, 99),
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "pdpbench:", err)
		os.Exit(1)
	}
}
