package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	workload "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"google.golang.org/grpc"
)

type workloadServer struct {
	workload.UnimplementedSpiffeWorkloadAPIServer
	initial *workload.X509SVIDResponse
	updates chan *workload.X509SVIDResponse
}

func (s *workloadServer) FetchX509SVID(_ *workload.X509SVIDRequest, stream grpc.ServerStreamingServer[workload.X509SVIDResponse]) error {
	if err := stream.Send(s.initial); err != nil {
		return err
	}
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case update := <-s.updates:
			if err := stream.Send(update); err != nil {
				return err
			}
		}
	}
}

type certificateAuthority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func testCA(t *testing.T, serial int64) certificateAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificateAuthority{cert: cert, key: key}
}
func (c certificateAuthority) issue(t *testing.T, id string, serial int64) (*x509svid.SVID, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(id)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), URIs: []*url.URL{uri}, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return &x509svid.SVID{ID: spiffeid.RequireFromString(id), Certificates: []*x509.Certificate{cert}, PrivateKey: key}, pkcs8
}
func responseFor(ca certificateAuthority, svid *x509svid.SVID, key []byte) *workload.X509SVIDResponse {
	return &workload.X509SVIDResponse{Svids: []*workload.X509SVID{{SpiffeId: svid.ID.String(), X509Svid: svid.Certificates[0].Raw, X509SvidKey: key, Bundle: ca.cert.Raw}}}
}

// This exercises our real Workload API source and TLS listener, including source
// rotation and principal-map reload, rather than injecting a fake TLS state.
func TestSPIFFERotation(t *testing.T) {
	ca := testCA(t, 1)
	serverSVID, key := ca.issue(t, "spiffe://example.test/pdp", 11)
	clientSVID, _ := ca.issue(t, "spiffe://example.test/client", 21)
	api := &workloadServer{initial: responseFor(ca, serverSVID, key), updates: make(chan *workload.X509SVIDResponse, 1)}
	socket := filepath.Join(t.TempDir(), "api.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	grpcServer := grpc.NewServer()
	workload.RegisterSpiffeWorkloadAPIServer(grpcServer, api)
	go grpcServer.Serve(listener)
	t.Cleanup(grpcServer.Stop)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	source, err := NewSPIFFE(ctx, "unix://"+socket, map[string]string{clientSVID.ID.String(): "alice"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { source.Close() })
	var current atomic.Pointer[SPIFFE]
	current.Store(source)
	httpServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, err := current.Load().Authenticate(r)
		if err != nil {
			w.WriteHeader(401)
			return
		}
		io.WriteString(w, identity.Principal)
	}), ErrorLog: log.New(io.Discard, "", 0)}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go httpServer.Serve(tls.NewListener(tcp, source.TLSConfig()))
	t.Cleanup(func() { httpServer.Close() })
	bundle := x509bundle.FromX509Authorities(spiffeid.RequireTrustDomainFromString("example.test"), []*x509.Certificate{ca.cert})
	makeClient := func(svid *x509svid.SVID) *http.Client {
		transport := &http.Transport{DisableKeepAlives: true, TLSClientConfig: tlsconfig.MTLSClientConfig(svid, bundle, tlsconfig.AuthorizeID(serverSVID.ID))}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport, Timeout: 2 * time.Second}
	}
	client := makeClient(clientSVID)
	endpoint := "https://" + tcp.Addr().String()
	get := func() (*http.Response, string) {
		t.Helper()
		r, err := client.Get(endpoint)
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
	first, principal := get()
	if first.StatusCode != 200 || principal != "alice" || first.TLS.PeerCertificates[0].SerialNumber.Int64() != 11 {
		t.Fatalf("initial SPIFFE identity not authenticated: %d %s", first.StatusCode, principal)
	}
	updated := source.source.Updated()
	rotated, rotatedKey := ca.issue(t, serverSVID.ID.String(), 12)
	api.updates <- responseFor(ca, rotated, rotatedKey)
	select {
	case <-updated:
	case <-time.After(2 * time.Second):
		t.Fatal("Workload API rotation was not consumed")
	}
	second, principal := get()
	if second.StatusCode != 200 || principal != "alice" || second.TLS.PeerCertificates[0].SerialNumber.Int64() != 12 {
		t.Fatal("new TLS handshake did not use rotated SVID")
	}
	mapping, err := source.WithPrincipals(map[string]string{clientSVID.ID.String(): "bob"})
	if err != nil {
		t.Fatal(err)
	}
	current.Store(mapping)
	_, principal = get()
	if principal != "bob" {
		t.Fatal("request retained listener's old principal map")
	}
	other, _ := ca.issue(t, "spiffe://example.test/unbound", 22)
	response, err := makeClient(other).Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatal("unbound trusted identity accepted")
	}
	forgedCA := testCA(t, 2)
	forged, _ := forgedCA.issue(t, clientSVID.ID.String(), 31)
	if response, err := makeClient(forged).Get(endpoint); err == nil {
		response.Body.Close()
		t.Fatal("forged SPIFFE URI accepted without trusted chain")
	}
	plain := &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: tlsconfig.TLSClientConfig(bundle, tlsconfig.AuthorizeID(serverSVID.ID))}}
	if response, err := plain.Get(endpoint); err == nil {
		response.Body.Close()
		t.Fatal("missing client certificate accepted")
	}
}
