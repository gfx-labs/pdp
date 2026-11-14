package auth

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// SPIFFE uses the maintained Workload API source for live SVID and bundle rotation.
// Every ID the bundle verifies reaches policy, which must deny the ones it does not name.
type SPIFFE struct {
	source *workloadapi.X509Source
}

func NewSPIFFE(ctx context.Context, endpoint string) (*SPIFFE, error) {
	if !strings.HasPrefix(endpoint, "unix:///") {
		return nil, errors.New("invalid SPIFFE configuration")
	}
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(endpoint)))
	if err != nil {
		return nil, errors.New("cannot initialize SPIFFE Workload API")
	}
	return &SPIFFE{source: source}, nil
}

func (s *SPIFFE) TLSConfig() *tls.Config {
	// Policy authorizes the exact identity per request, not the listener.
	cfg := tlsconfig.MTLSServerConfig(s.source, s.source, tlsconfig.AuthorizeAny())
	cfg.MinVersion = tls.VersionTLS13
	cfg.SessionTicketsDisabled = true
	cfg.NextProtos = []string{"http/1.1"}
	return cfg
}

// ClientTLSConfig presents the current SVID and accepts only a server whose
// SPIFFE ID is exactly id.
func (s *SPIFFE) ClientTLSConfig(id spiffeid.ID) *tls.Config {
	cfg := tlsconfig.MTLSClientConfig(s.source, s.source, tlsconfig.AuthorizeID(id))
	cfg.MinVersion = tls.VersionTLS13
	return cfg
}

func (s *SPIFFE) Authenticate(r *http.Request) (Identity, error) {
	if r.TLS == nil || !r.TLS.HandshakeComplete || len(r.TLS.PeerCertificates) == 0 {
		return Identity{}, ErrUnauthenticated
	}
	// Recheck the current bundle on every request, including reused connections.
	id, _, err := x509svid.Verify(r.TLS.PeerCertificates, s.source)
	if err != nil {
		return Identity{}, ErrUnauthenticated
	}
	return Identity{Method: "spiffe", SPIFFEID: id.String()}, nil
}

func (s *SPIFFE) Close() error { return s.source.Close() }
