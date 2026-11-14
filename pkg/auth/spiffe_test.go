package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	workload "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/gfx-labs/pdp/internal/spiffetest"
)

// This exercises our real Workload API source and TLS listener, including source
// rotation, rather than injecting a fake TLS state.
func TestSPIFFERotation(t *testing.T) {
	ca := spiffetest.NewCA(t, 1)
	serverSVID, key := ca.Issue(t, "spiffe://example.test/pdp", 11)
	clientSVID, _ := ca.Issue(t, "spiffe://example.test/client", 21)
	api := &spiffetest.WorkloadAPI{Initial: ca.Response(serverSVID, key), Updates: make(chan *workload.X509SVIDResponse, 1)}
	endpoint := spiffetest.Serve(t, api)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	source, err := NewSPIFFE(ctx, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { source.Close() })
	httpServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, err := source.Authenticate(r)
		if err != nil {
			w.WriteHeader(401)
			return
		}
		io.WriteString(w, identity.ID())
	}), ErrorLog: log.New(io.Discard, "", 0)}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go httpServer.Serve(tls.NewListener(tcp, source.TLSConfig()))
	t.Cleanup(func() { httpServer.Close() })
	bundle := x509bundle.FromX509Authorities(spiffeid.RequireTrustDomainFromString("example.test"), []*x509.Certificate{ca.Cert})
	makeClient := func(svid *x509svid.SVID) *http.Client {
		transport := &http.Transport{DisableKeepAlives: true, TLSClientConfig: tlsconfig.MTLSClientConfig(svid, bundle, tlsconfig.AuthorizeID(serverSVID.ID))}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport, Timeout: 2 * time.Second}
	}
	client := makeClient(clientSVID)
	target := "https://" + tcp.Addr().String()
	get := func() (*http.Response, string) {
		t.Helper()
		r, err := client.Get(target)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		return r, string(data)
	}
	first, id := get()
	if first.StatusCode != 200 || id != clientSVID.ID.String() || first.TLS.PeerCertificates[0].SerialNumber.Int64() != 11 {
		t.Fatalf("initial SPIFFE identity not authenticated: %d %s", first.StatusCode, id)
	}
	updated := source.source.Updated()
	rotated, rotatedKey := ca.Issue(t, serverSVID.ID.String(), 12)
	api.Updates <- ca.Response(rotated, rotatedKey)
	select {
	case <-updated:
	case <-time.After(2 * time.Second):
		t.Fatal("Workload API rotation was not consumed")
	}
	second, id := get()
	if second.StatusCode != 200 || id != clientSVID.ID.String() || second.TLS.PeerCertificates[0].SerialNumber.Int64() != 12 {
		t.Fatal("new TLS handshake did not use rotated SVID")
	}
	// A second trusted workload is reported as itself, so policy can tell them apart.
	other, _ := ca.Issue(t, "spiffe://example.test/other", 22)
	response, err := makeClient(other).Get(target)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || string(data) != other.ID.String() {
		t.Fatalf("second trusted identity misreported: %d %s", response.StatusCode, data)
	}
	forgedCA := spiffetest.NewCA(t, 2)
	forged, _ := forgedCA.Issue(t, clientSVID.ID.String(), 31)
	if response, err := makeClient(forged).Get(target); err == nil {
		response.Body.Close()
		t.Fatal("forged SPIFFE URI accepted without trusted chain")
	}
	plain := &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: tlsconfig.TLSClientConfig(bundle, tlsconfig.AuthorizeID(serverSVID.ID))}}
	if response, err := plain.Get(target); err == nil {
		response.Body.Close()
		t.Fatal("missing client certificate accepted")
	}
}
