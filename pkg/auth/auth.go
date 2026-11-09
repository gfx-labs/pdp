// Package auth authenticates operating-system or verified SPIFFE identities.
package auth

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
)

var ErrUnauthenticated = errors.New("authentication required")

type Identity struct {
	Principal string
	Method    string
	UID       uint32
	SPIFFEID  string
}

type Authenticator interface {
	Authenticate(*http.Request) (Identity, error)
}

type peerKey struct{}
type peerIdentity struct {
	uid   uint32
	valid bool
}

// Unix maps kernel-authenticated UIDs, not caller-controlled headers, to principals.
// Processes sharing a UID share this authority. PID and systemd unit are not identities.
type Unix struct{ principals map[uint32]string }

func NewUnix(principals map[uint32]string) (*Unix, error) {
	if len(principals) == 0 {
		return nil, errors.New("at least one UID binding is required")
	}
	u := &Unix{principals: make(map[uint32]string, len(principals))}
	for uid, p := range principals {
		if !validPrincipal(p) {
			return nil, errors.New("invalid principal binding")
		}
		u.principals[uid] = p
	}
	return u, nil
}

func validPrincipal(p string) bool {
	if len(p) == 0 || len(p) > 256 {
		return false
	}
	for _, c := range p {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

// ConnContext must be installed on the HTTP server accepting the Unix listener.
func (u *Unix) ConnContext(ctx context.Context, c net.Conn) context.Context {
	return ConnContext(ctx, c)
}

func ConnContext(ctx context.Context, c net.Conn) context.Context {
	uid, err := peerUID(c)
	return context.WithValue(ctx, peerKey{}, peerIdentity{uid: uid, valid: err == nil})
}

func (u *Unix) Authenticate(r *http.Request) (Identity, error) {
	peer, ok := r.Context().Value(peerKey{}).(peerIdentity)
	if !ok || !peer.valid {
		return Identity{}, ErrUnauthenticated
	}
	p, ok := u.principals[peer.uid]
	if !ok {
		return Identity{}, ErrUnauthenticated
	}
	return Identity{Principal: p, Method: "unix", UID: peer.uid}, nil
}

// ListenUnix never removes an existing path. Its parent must be administrator-owned.
func ListenUnix(path string, mode os.FileMode) (net.Listener, error) {
	if !filepath.IsAbs(path) || mode.Perm() == 0 || mode & ^os.FileMode(0770) != 0 || mode.Perm()&0007 != 0 {
		return nil, errors.New("invalid Unix socket path or mode")
	}
	return listenUnix(path, mode)
}
