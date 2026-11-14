// Package spiffetest runs a local Workload API server over a generated CA, so
// tests use the real go-spiffe source and TLS handshakes without SPIRE.
package spiffetest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	workload "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"google.golang.org/grpc"
)

// WorkloadAPI sends Initial to every stream, then each value from Updates.
type WorkloadAPI struct {
	workload.UnimplementedSpiffeWorkloadAPIServer
	Initial *workload.X509SVIDResponse
	Updates chan *workload.X509SVIDResponse
}

func (s *WorkloadAPI) FetchX509SVID(_ *workload.X509SVIDRequest, stream grpc.ServerStreamingServer[workload.X509SVIDResponse]) error {
	if err := stream.Send(s.Initial); err != nil {
		return err
	}
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case update := <-s.Updates:
			if err := stream.Send(update); err != nil {
				return err
			}
		}
	}
}

// Serve starts the server on a Unix socket in a test directory and returns
// its endpoint in the form the Workload API client takes.
func Serve(t *testing.T, api *WorkloadAPI) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "api.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	workload.RegisterSpiffeWorkloadAPIServer(server, api)
	go server.Serve(listener)
	t.Cleanup(server.Stop)
	return "unix://" + socket
}

type CA struct {
	Cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func NewCA(t *testing.T, serial int64) CA {
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
	return CA{Cert: cert, key: key}
}

// Issue returns an SVID for id and its PKCS #8 key, as the Workload API sends it.
func (c CA) Issue(t *testing.T, id string, serial int64) (*x509svid.SVID, []byte) {
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
	der, err := x509.CreateCertificate(rand.Reader, template, c.Cert, &key.PublicKey, c.key)
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

func (c CA) Response(svid *x509svid.SVID, key []byte) *workload.X509SVIDResponse {
	return &workload.X509SVIDResponse{Svids: []*workload.X509SVID{{SpiffeId: svid.ID.String(), X509Svid: svid.Certificates[0].Raw, X509SvidKey: key, Bundle: c.Cert.Raw}}}
}
