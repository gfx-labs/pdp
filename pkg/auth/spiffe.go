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
type SPIFFE struct {
	source     *workloadapi.X509Source
	principals map[string]string
}

func NewSPIFFE(ctx context.Context, endpoint string, principals map[string]string) (*SPIFFE, error) {
	if !strings.HasPrefix(endpoint, "unix:///") || len(principals) == 0 {
		return nil, errors.New("invalid SPIFFE configuration")
	}
	s := &SPIFFE{principals: make(map[string]string, len(principals))}
	for id, p := range principals {
		if _, err := spiffeid.FromString(id); err != nil || !validPrincipal(p) {
			return nil, errors.New("invalid SPIFFE principal binding")
		}
		s.principals[id] = p
	}
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(endpoint)))
	if err != nil {
		return nil, errors.New("cannot initialize SPIFFE Workload API")
	}
	s.source = source
	return s, nil
}

func (s *SPIFFE) TLSConfig() *tls.Config {
	// Exact identity authorization is snapshot-scoped, not pinned to a listener.
	cfg := tlsconfig.MTLSServerConfig(s.source, s.source, tlsconfig.AuthorizeAny())
	cfg.MinVersion = tls.VersionTLS13
	cfg.SessionTicketsDisabled = true
	cfg.NextProtos = []string{"http/1.1"}
	return cfg
}

// WithPrincipals creates an immutable mapping sharing the rotating source.
// The original source owner must Close only after every snapshot has drained.
func (s *SPIFFE) WithPrincipals(principals map[string]string) (*SPIFFE, error) {
	if len(principals) == 0 {
		return nil, errors.New("SPIFFE principal bindings are required")
	}
	next := &SPIFFE{source: s.source, principals: make(map[string]string, len(principals))}
	for id, p := range principals {
		if _, err := spiffeid.FromString(id); err != nil || !validPrincipal(p) {
			return nil, errors.New("invalid SPIFFE principal binding")
		}
		next.principals[id] = p
	}
	return next, nil
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
	p, ok := s.principals[id.String()]
	if !ok {
		return Identity{}, ErrUnauthenticated
	}
	return Identity{Principal: p, Method: "spiffe", SPIFFEID: id.String()}, nil
}

func (s *SPIFFE) Close() error { return s.source.Close() }
