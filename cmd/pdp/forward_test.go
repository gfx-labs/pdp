package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/gfx-labs/pdp/internal/spiffetest"
	"github.com/gfx-labs/pdp/pkg/auth"
)

// lockedBuffer is written by connection goroutines and read by the test.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// The gateway side is the listener serve builds, and each side reads its SVID
// from its own local Workload API server. Nothing of PDP is replaced.
func TestForwardPresentsWorkloadSVID(t *testing.T) {
	const gatewayID, workloadID = "spiffe://example.test/pdp", "spiffe://example.test/worker"
	ca := spiffetest.NewCA(t, 1)
	source := func(id string, serial int64) *auth.SPIFFE {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		s, err := auth.NewSPIFFE(ctx, spiffetest.Serve(t, &spiffetest.WorkloadAPI{Initial: ca.Response(ca.Issue(t, id, serial))}))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	}
	gatewaySource, workloadSource := source(gatewayID, 11), source(workloadID, 21)
	listen := func() *net.TCPListener {
		t.Helper()
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return l.(*net.TCPListener)
	}

	var served atomic.Int32
	gateway := tls.NewListener(listen(), gatewaySource.TLSConfig())
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		identity, err := gatewaySource.Authenticate(r)
		if err != nil {
			w.WriteHeader(401)
			return
		}
		io.WriteString(w, identity.ID()+" "+r.RequestURI)
	}), ErrorLog: log.New(io.Discard, "", 0)}
	go server.Serve(gateway)
	t.Cleanup(func() { server.Close() })

	// This gateway answers only after the client has finished sending.
	halfClose := tls.NewListener(listen(), gatewaySource.TLSConfig())
	t.Cleanup(func() { halfClose.Close() })
	go func() {
		for {
			conn, err := halfClose.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				data, err := io.ReadAll(conn)
				if err == nil {
					conn.Write(append([]byte("received "), data...))
				}
			}()
		}
	}()

	var logs lockedBuffer
	start := func(target, expectedID string) string {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		l := listen()
		done := make(chan error, 1)
		go func() {
			done <- forward(ctx, l, target, workloadSource.ClientTLSConfig(spiffeid.RequireFromString(expectedID)), log.New(&logs, "", 0))
		}()
		t.Cleanup(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(3 * time.Second):
				t.Error("forward did not stop")
			}
		})
		return l.Addr().String()
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{DisableKeepAlives: true, Proxy: nil}}

	// A proxy-aware client sends absolute-form to the loopback port in plain HTTP.
	request := func(forwarder string) (*http.Response, error) {
		r, err := http.NewRequest("GET", "http://"+forwarder+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.URL.Opaque = "https://api.example.test/resource"
		return client.Do(r)
	}
	response, err := request(start(gateway.Addr().String(), gatewayID))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != workloadID+" https://api.example.test/resource" {
		t.Fatalf("gateway saw %q, %v", body, err)
	}

	conn, err := net.Dial("tcp", start(halfClose.Addr().String(), gatewayID))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = io.WriteString(conn, "request"); err != nil {
		t.Fatal(err)
	}
	if err = conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if reply, err := io.ReadAll(conn); err != nil || string(reply) != "received request" {
		t.Fatalf("after half-close the client read %q, %v", reply, err)
	}
	if logs.String() != "" {
		t.Fatalf("successful connections were logged: %s", logs.String())
	}

	// The same gateway is refused when its ID is not the expected one.
	before := served.Load()
	if response, err := request(start(gateway.Addr().String(), "spiffe://example.test/other")); err == nil {
		response.Body.Close()
		t.Fatal("gateway with an unexpected SPIFFE ID was accepted")
	}
	if served.Load() != before {
		t.Fatal("request reached a gateway with an unexpected SPIFFE ID")
	}
	if strings.Count(logs.String(), "\n") != 1 {
		t.Fatalf("want one log line for the refused gateway, got %q", logs.String())
	}
}

// The check is what a Kubernetes exec probe runs. It passes against a running
// forwarder without making that forwarder contact its gateway, and fails
// against a port nothing listens on.
func TestForwardCheck(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gateway := closed.Addr().String()
	closed.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var logs lockedBuffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	// No gateway listens, so any attempt to reach it would be logged as a failure.
	go func() {
		done <- forward(ctx, listener.(*net.TCPListener), gateway, &tls.Config{}, log.New(&logs, "", 0))
	}()
	var out, errout bytes.Buffer
	if err = run([]string{"forward", "--check", "--listen", listener.Addr().String()}, &out, &errout); err != nil {
		t.Fatalf("check against a running forwarder: %v", err)
	}
	cancel()
	// forward returns only after every accepted connection has been handled.
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if logs.String() != "" || out.Len() != 0 || errout.Len() != 0 {
		t.Fatalf("the check made the forwarder dial its gateway or printed: %q %q %q", logs.String(), out.String(), errout.String())
	}
	if err = run([]string{"forward", "--check", "--listen", gateway}, &out, &errout); err == nil {
		t.Fatal("check passed against a port nothing listens on")
	}
}

func TestForwardListenAddressMustBeLoopback(t *testing.T) {
	for address, valid := range map[string]bool{
		"127.0.0.1:3128": true,
		"[::1]:3128":     true,
		"0.0.0.0:3128":   false,
		"[::]:3128":      false,
		":3128":          false,
		"localhost:3128": false,
		"10.0.0.5:3128":  false,
		"127.0.0.1":      false,
		"127.0.0.1:0":    false,
	} {
		if err := loopbackListenAddress(address); (err == nil) != valid {
			t.Errorf("%s: valid=%v, got %v", address, valid, err)
		}
	}
}
