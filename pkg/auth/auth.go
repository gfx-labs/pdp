// Package auth authenticates operating-system or verified SPIFFE identities.
package auth

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

var ErrUnauthenticated = errors.New("authentication required")

// Identity holds only verified facts. Policy decides what an identity may do.
type Identity struct {
	Method   string
	UID      uint32
	SPIFFEID string
	IP       string
}

// ID is the SPIFFE ID, "uid:<n>" for a Unix peer or "ip:<address>" for a
// transparently steered connection.
func (i Identity) ID() string {
	switch i.Method {
	case "spiffe":
		return i.SPIFFEID
	case "transparent":
		return "ip:" + i.IP
	}
	return "uid:" + strconv.FormatUint(uint64(i.UID), 10)
}

type Authenticator interface {
	Authenticate(*http.Request) (Identity, error)
}

type peerKey struct{}
type peerIdentity struct {
	uid   uint32
	valid bool
}

// Unix reports the kernel-authenticated peer UID, never caller-controlled headers.
// Every connecting UID reaches policy, which must deny the ones it does not name.
// Processes sharing a UID share an identity. PID and systemd unit are not identities.
type Unix struct{}

func NewUnix() *Unix { return &Unix{} }

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
	return Identity{Method: "unix", UID: peer.uid}, nil
}

// ListenUnix never removes an existing path. Its parent must be administrator-owned.
func ListenUnix(path string, mode os.FileMode) (net.Listener, error) {
	if !filepath.IsAbs(path) || mode.Perm() == 0 || mode & ^os.FileMode(0770) != 0 || mode.Perm()&0007 != 0 {
		return nil, errors.New("invalid Unix socket path or mode")
	}
	return listenUnix(path, mode)
}
